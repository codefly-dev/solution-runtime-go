// installreceiver is a process fixture for the Accounts installation crossing.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	solution "github.com/codefly-dev/solution-runtime-go"
	recordsv1 "github.com/obin-ai/module-record-store/clients/go/records/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	id := os.Getenv("SOLUTION_ID")
	path := os.Getenv("INSTALL_RECEIVER_LOG")
	outcome := os.Getenv("INSTALL_RECEIVER_OUTCOME")
	schemaPath := os.Getenv("INSTALL_RECEIVER_SCHEMA")
	if id == "" || path == "" || (outcome != "ack" && outcome != "refuse" && outcome != "fail") {
		log.Fatal("SOLUTION_ID, INSTALL_RECEIVER_LOG and a valid INSTALL_RECEIVER_OUTCOME are required")
	}
	var schema recordsv1.RecordType
	if schemaPath != "" {
		data, err := os.ReadFile(schemaPath)
		if err != nil {
			log.Fatal(err)
		}
		if err := protojson.Unmarshal(data, &schema); err != nil {
			log.Fatal(err)
		}
	}
	step := func(ctx context.Context, installation solution.Installation) error {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("open observation log: %w", err)
		}
		err = json.NewEncoder(file).Encode(installation)
		closeErr := file.Close()
		if err != nil {
			return fmt.Errorf("write observation: %w", err)
		}
		if closeErr != nil {
			return fmt.Errorf("close observation log: %w", closeErr)
		}
		switch outcome {
		case "refuse":
			return solution.RefuseInstall("fixture refused installation")
		case "fail":
			return errors.New("fixture installation failed")
		default:
			if schemaPath == "" {
				return nil
			}
			request := &recordsv1.DefineRecordTypeRequest{Name: schema.GetName(), Type: &schema}
			first := &recordsv1.DefineRecordTypeResponse{}
			if err := installation.Call(ctx, "records", recordsv1.RecordsService_DefineRecordType_FullMethodName, request, first); err != nil {
				return fmt.Errorf("define schema: %w", err)
			}
			again := &recordsv1.DefineRecordTypeResponse{}
			if err := installation.Call(ctx, "records", recordsv1.RecordsService_DefineRecordType_FullMethodName, request, again); err != nil {
				return fmt.Errorf("repeat schema: %w", err)
			}
			if first.GetType().GetTypeId() == "" || first.GetType().GetTypeRevision() == "" || again.GetMinted() || first.GetType().GetTypeId() != again.GetType().GetTypeId() || first.GetType().GetTypeRevision() != again.GetType().GetTypeRevision() {
				return errors.New("schema definition did not converge")
			}
			if err := installation.Call(ctx, "records", recordsv1.RecordsService_DefineProjection_FullMethodName, &recordsv1.DefineProjectionRequest{}, &recordsv1.DefineProjectionResponse{}); err == nil {
				return errors.New("undeclared method was accepted")
			}
			return nil
		}
	}
	server := solution.New(solution.Manifest{ID: id})
	if schemaPath == "" {
		server.OnInstall(step)
	} else {
		server.OnInstall(step, solution.SetupModule{As: "records", Authority: solution.AuthorityRelay{Group: "records", EndpointKey: "ENDPOINT", BindingKey: "BINDING"}, Methods: []string{recordsv1.RecordsService_DefineRecordType_FullMethodName}})
	}
	if err := server.Serve(); err != nil {
		log.Fatal(err)
	}
}
