package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/Jeffail/gabs/v2"
	"github.com/infosecwatchman/eyeSegmentAPI/eyeSegmentAPI"
	"io"
	"log"
	"regexp"
	"strconv"
	"strings"
)

type edge struct {
	num         int
	From        string        `json:"from"`
	To          string        `json:"to"`
	ID          string        `json:"id"`
	Connections []connectData `json:"connections"`
}

type connectData struct {
	NumOfConnections int    `json:"#Connections"`
	First_Seen       string `json:"First_Seen"`
	Last_Seen        string `json:"Last_Seen"`
	Port             int    `json:"Port"`
	Protocol         string `json:"Protocol"`
	Service_Name     string `json:"Service_Name"`
}

func DataStream() string {
	log.Println("Running DataStream")
	MatrixData := gabs.New()
	MatrixData.Array("edges")
	MatrixData.Array("nodes")
	dataContainer, err := gabs.ParseJSON(eyeSegmentAPI.GetMatrixData())
	if err != nil {
		log.Println(err)
	}
	if dataContainer.ExistsP("data.0.srcZone") {
		for _, data := range dataContainer.S("data").Children() {
			jsonData := CSVtoJSON(eyeSegmentAPI.GetCSVData(trimQuote(data.S("srcZone").String()), trimQuote(data.S("dstZone").String())))
			nodes1 := MatrixData.Path("nodes").Children()
			nodes2 := jsonData.Path("nodes").Children()

			// Create a new container to store the merged edges and nodes
			mergedContainer := gabs.New()

			var edges1, edges2 []edge
			json.Unmarshal(MatrixData.S("edges").EncodeJSON(), &edges1)
			json.Unmarshal(jsonData.S("edges").EncodeJSON(), &edges2)
			for _, jsonEdge := range edges2 {
				edges1 = append(edges1, jsonEdge)
			}
			mergedContainer.Array("edges")
			marshalledEdges, _ := json.Marshal(edges1)
			mergedEdgesContainer, _ := gabs.ParseJSON(marshalledEdges)
			mergedContainer.Set(mergedEdgesContainer.Data(), "edges")

			// Merge the nodes arrays
			mergedContainer.Array("nodes")
			for _, node := range nodes1 {
				mergedContainer.ArrayAppend(node.Data(), "nodes")
			}
			for _, node := range nodes2 {
				mergedContainer.ArrayAppend(node.Data(), "nodes")
			}
			MatrixData = mergedContainer
		}
	}
	//fmt.Println(strings.ReplaceAll(CSVtoJSON(eyeSegmentAPI.GetCSVData("g_2718281828459045235", "g_1234567890123456789")).String(), `\"`, ""))
	//return strings.ReplaceAll(CSVtoJSON(eyeSegmentAPI.GetCSVData("g_2718281828459045235", "g_1234567890123456789")).String(), `\"`, "")
	//fmt.Println(MatrixData.String())
	return strings.ReplaceAll(MatrixData.String(), `\"`, "")
}

func trimQuote(s string) string {
	if len(s) > 0 && s[0] == '"' {
		s = s[1:]
	}
	if len(s) > 0 && s[len(s)-1] == '"' {
		s = s[:len(s)-1]
	}
	return s
}

func CSVtoJSON(importcsvdata io.Reader) *gabs.Container {
	csvdata := csv.NewReader(importcsvdata)
	records, err := csvdata.ReadAll()
	if err != nil {
		log.Fatalln(err)
	}
	fulljson := gabs.New()
	fulljson.Array("edges")
	fulljson.Array("nodes")
	var edges []edge
	var headers []string
	for rownum, row := range records {
		//fmt.Printf("%d: %s\n", row, record)
		if rownum == 0 {
			headers = row
		} else {
			jsonSRCNodePart := gabs.New()
			jsonDSTNodePart := gabs.New()
			jsonEdgePart := gabs.New()
			connectionData := gabs.New()
			connectionData.Array("connectionData")
			//realJsonEdgePart := gabs.New()
			//realJsonEdgePart.Array("data")

			for fieldnum, field := range row {
				tempsrcjson := gabs.New()
				tempdstjson := gabs.New()
				for columnnum, column := range headers {

					if columnnum == fieldnum {
						if strings.Contains(column, "Source") {
							if !strings.Contains(column, "IP") || !strings.Contains(column, "DNS") {
								tempsrcjson.Set(field, strings.ReplaceAll(column, "Source_", ""))
							}
						}
						if strings.Contains(column, "Destination") {
							if !strings.Contains(column, "IP") || !strings.Contains(column, "DNS") {
								tempdstjson.Set(field, strings.ReplaceAll(column, "Destination_", ""))
							}
						}
					}
				}
				for columnnum, column := range headers {
					if columnnum == fieldnum {
						if column == "Source_IP" {
							regex, _ := regexp.Compile(fmt.Sprintf(`"id":"%s"`, field))
							if !regex.MatchString(fulljson.Search("nodes").String()) {
								jsonDSTNodePart.Set(field, "id")
							}
						}
						if column == "Destination_IP" {
							regex, _ := regexp.Compile(fmt.Sprintf(`"id":"%s"`, field))
							if !regex.MatchString(fulljson.Search("nodes").String()) {
								jsonSRCNodePart.Set(field, "id")
							}
						}
						if column == "Source_IP" {
							jsonEdgePart.Set(field, "from")
						}
						if column == "Destination_IP" {
							jsonEdgePart.Set(field, "to")
						}
						if !strings.Contains(column, "Destination") && !strings.Contains(column, "Source") {
							jsonEdgePart.Set(field, column)
						}
						jsonDSTNodePart.Merge(tempsrcjson)
						jsonSRCNodePart.Merge(tempdstjson)

					}
				}
			}
			from := jsonEdgePart.S("from").Data()
			to := jsonEdgePart.S("to").Data()
			id := fmt.Sprintf("%s%s", jsonEdgePart.S("to").Data(), jsonEdgePart.S("from").Data())

			connectionData.Set(from, "from")
			connectionData.Set(to, "to")
			connectionData.Set(id, "id")
			jsonEdgePart.Delete("from")
			jsonEdgePart.Delete("to")
			connectionData.ArrayAppend(jsonEdgePart, "connectionData")

			regex, _ := regexp.Compile(`"id"`)
			if regex.MatchString(jsonSRCNodePart.String()) {
				fulljson.ArrayAppend(jsonSRCNodePart, "nodes")
			}
			if regex.MatchString(jsonDSTNodePart.String()) {
				fulljson.ArrayAppend(jsonDSTNodePart, "nodes")
			}

			IdRegex, _ := regexp.Compile(fmt.Sprintf(`"id":"%s"`, id))
			compiledJson, _ := json.Marshal(edges)
			if !IdRegex.MatchString(string(compiledJson)) {
				var newedge edge
				newedge.ID = trimQuote(connectionData.S("id").String())
				newedge.From = trimQuote(connectionData.S("from").String())
				newedge.To = trimQuote(connectionData.S("to").String())
				NumofConnections, _ := strconv.Atoi(trimQuote(jsonEdgePart.S("#Connections").String()))
				port, _ := strconv.Atoi(trimQuote(jsonEdgePart.S("Port").String()))
				newedge.Connections = append(newedge.Connections, connectData{
					NumOfConnections: NumofConnections,
					First_Seen:       trimQuote(jsonEdgePart.S("First_Seen").String()),
					Last_Seen:        trimQuote(jsonEdgePart.S("Last_Seen").String()),
					Port:             port,
					Protocol:         trimQuote(jsonEdgePart.S("Protocol").String()),
					Service_Name:     trimQuote(jsonEdgePart.S("Service_Name").String()),
				})
				edges = append(edges, newedge)
			} else {
				for edgeID, edge := range edges {
					if edge.ID == id {
						var newConnection connectData
						NumofConnections, _ := strconv.Atoi(trimQuote(jsonEdgePart.S("#Connections").String()))
						port, _ := strconv.Atoi(trimQuote(jsonEdgePart.S("Port").String()))
						newConnection = connectData{
							NumOfConnections: NumofConnections,
							First_Seen:       trimQuote(jsonEdgePart.S("First_Seen").String()),
							Last_Seen:        trimQuote(jsonEdgePart.S("Last_Seen").String()),
							Port:             port,
							Protocol:         trimQuote(jsonEdgePart.S("Protocol").String()),
							Service_Name:     trimQuote(jsonEdgePart.S("Service_Name").String()),
						}
						edges[edgeID].Connections = append(edges[edgeID].Connections, newConnection)
					}
				}
			}
		}
	}
	jsonByte, _ := json.Marshal(edges)
	compiledJson, _ := gabs.ParseJSON(jsonByte)
	fulljson.Set(compiledJson, "edges")
	return fulljson
}
