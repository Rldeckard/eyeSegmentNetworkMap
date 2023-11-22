package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/cheggaaa/pb/v3"
	"github.com/infosecwatchman/eyeSegmentAPI/eyeSegmentAPI"
	"golang.org/x/exp/slices"
)

func DataStream() string {
	log.Println("Running DataStream")
	dataContainer, err := gabs.ParseJSON(eyeSegmentAPI.GetMatrixData())
	if err != nil {
		log.Println(err)
	}
	var columnNamesMaster []string
	var concatenatedData [][]string
	var jsonMatrix string
	start := time.Now()
	if dataContainer.ExistsP("data.0.srcZone") {
		waitgroup := sync.WaitGroup{}
		for count, data := range dataContainer.S("data").Children() {
			waitgroup.Add(1)
			go func(data *gabs.Container, count int) {
				defer waitgroup.Done()
				CSVData := eyeSegmentAPI.GetCSVData(trimQuote(data.S("srcZone").String()), trimQuote(data.S("dstZone").String()))
				csvdata := csv.NewReader(CSVData)
				records, err := csvdata.ReadAll()
				if err != nil {
					log.Fatalln(err)
				}

				for rownum, row := range records {
					if rownum == 0 {
						if len(columnNamesMaster) == 0 {
							columnNamesMaster = row
						} else {
							for columnNum, cell := range row {
								if !slices.Contains(columnNamesMaster, cell) {
									if strings.Contains(cell, "Level") {
										level, _ := strconv.Atoi(strings.Split(cell, "Level_")[1])
										index := slices.Index(columnNamesMaster, fmt.Sprintf("%sLevel_%d", strings.Split(cell, "Level_")[0], level-1))
										columnNamesMaster = slices.Insert(columnNamesMaster, index+1, cell)
									} else {
										columnNamesMaster[columnNum] = cell
									}
								}
							}
						}
						break
					}
				}
			}(data, count)
		}
		waitgroup.Wait()
		fmt.Printf("Process Data from API: %s\n", time.Since(start))
		fmt.Println(columnNamesMaster)
		start = time.Now()
		bar := pb.StartNew(len(dataContainer.S("data").Children())).SetTemplate(pb.Simple).SetRefreshRate(100 * time.Millisecond)
		for count, data := range dataContainer.S("data").Children() {
			waitgroup.Add(1)
			go func(data *gabs.Container, count int) {
				defer waitgroup.Done()
				CSVData := eyeSegmentAPI.GetCSVData(trimQuote(data.S("srcZone").String()), trimQuote(data.S("dstZone").String()))
				csvdata := csv.NewReader(CSVData)
				records, err := csvdata.ReadAll()
				if err != nil {
					log.Fatalln(err)
				}
				columnNamesTemp := make([]string, len(columnNamesMaster))
				for rownum, row := range records {
					if rownum == 0 {
						columnNamesTemp = row
					} else {
						temprow := make([]string, len(columnNamesMaster))
						for cellColumnNum, cell := range row {
							temprow = slices.Insert(temprow, slices.Index(columnNamesMaster, columnNamesTemp[cellColumnNum]), cell)
						}
						concatenatedData = append(concatenatedData, temprow)
					}
				}
				//tracker++
				//fmt.Printf("Added %s to %s ||| %d out of %d complete.\n", trimQuote(data.S("srcZone").String()), trimQuote(data.S("dstZone").String()), tracker, len(dataContainer.S("data").Children()))
				bar.Increment()
			}(data, count)
		}
		waitgroup.Wait()
		for i := 0; i <= 50; i++ {
			if bar.Current() == int64(len(dataContainer.S("data").Children())) {
				bar.Finish()
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		fmt.Printf("Get Column Names from Data: %s\n", time.Since(start))
		var buffer bytes.Buffer
		/*
			fmt.Println("Creating file.")
			file, err := os.Create("result.csv")
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
		*/
		csvData := csv.NewWriter(&buffer)
		//defer csvData.Flush()
		fmt.Println("writing headers")
		err = csvData.Write(columnNamesMaster)
		if err != nil {
			fmt.Println(err)
		}
		for _, rows := range concatenatedData {
			if len(columnNamesMaster) > len(rows) {
				runtimes := 0
				for runtimes == (len(columnNamesMaster) - len(rows)) {
					fmt.Printf("looping %d", runtimes)
					rows = append(rows, "")
					runtimes++
				}
			}
			//fmt.Println("writing line")
			err = csvData.Write(rows)
			if err != nil {
				fmt.Println(err)
			}
		}
		csvData.Flush()
		if err := csvData.Error(); err != nil {
			panic(err)
		}
		start := time.Now()
		jsonMatrix = CSVtoJSON(strings.NewReader(buffer.String()))
		fmt.Printf("Converting JSON: %s\n", time.Since(start))
	}
	fmt.Println("exiting Datastream function.")
	//fmt.Println(MatrixData.String())

	return jsonMatrix
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

type Conn struct {
	SourceZone   string
	SourceIP     string
	SourceHost   string
	DestZone     string
	DestIP       string
	DestPort     string
	DestProtocol string
	timestamp    string
}

type edge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type node struct {
	ID string `json:"id"`
}

type connectData struct {
	NumOfConnections int    `json:"#Connections"`
	First_Seen       string `json:"First_Seen"`
	Last_Seen        string `json:"Last_Seen"`
	Port             int    `json:"Port"`
	Protocol         string `json:"Protocol"`
	Service_Name     string `json:"Service_Name"`
}

func CSVtoJSON(importcsvdata io.Reader) string {
	csvdata := csv.NewReader(importcsvdata)
	csvdata.FieldsPerRecord = -1
	records, err := csvdata.ReadAll()
	if err != nil {
		log.Fatalln(err)
	}

	var nodeList node
	var edgeList edge
	nodeMap := make(map[string]string)
	edgeMap := make(map[string]string)
	var edgeGroup []edge
	var nodeGroup []node
	fulljson := make(map[string]any)
	for rownum, row := range records {
		//assign value to key to make a list of unique values(keys are unique).
		//don't use slice/string contains here as it adds several seconds of delay.
		edgeMap[row[4]] = row[1]
		nodeMap[row[1]] = "Unused"
		nodeMap[row[4]] = "Unused"

		/*
			conn.SourceZone = row[0]
			conn.SourceIP = row[1]
			conn.SourceHost = row[2]
			conn.DestZone = row[3]
			conn.DestIP = row[4]
			conn.DestPort = row[5]
			conn.DestProtocol = row[6]
			conn.timestamp = row[9]
			nodeList[rownum] = conn
		*/
		if rownum > 2000 {
			break
		}

	}
	//convert unique keys to struct for JSON prep. No delay, 4ms
	for to, from := range edgeMap {
		edgeList.From = from
		edgeList.To = to
		edgeGroup = append(edgeGroup, edgeList)
	}
	for id, _ := range nodeMap {
		nodeList.ID = id
		nodeGroup = append(nodeGroup, nodeList)
	}
	fulljson["nodes"] = nodeGroup
	fulljson["edges"] = edgeGroup

	jBytes, _ := json.Marshal(fulljson)
	os.WriteFile("export.json", jBytes, 0644)
	return string(jBytes)
}
