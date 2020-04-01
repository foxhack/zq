package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/brimsec/zq/zqd/api"
)

func createSpace(ctx context.Context, conn *api.Connection, spacename, datadir string) error {
	err := conn.SpaceDelete(ctx, spacename)
	if err != nil {
		log.Println("skipping error deleting space", err)
	}

	_, err = conn.SpacePost(ctx, api.SpacePostRequest{
		Name:    spacename,
		DataDir: datadir,
	})
	if err != nil {
		return err
	}

	return nil
}

func ingest(ctx context.Context, pcapfile string) error {
	pcapfile, err := filepath.Abs(pcapfile)
	if err != nil {
		return err
	}
	datadir := pcapfile + ".brim"
	err = os.MkdirAll(datadir, 0700)
	if err != nil {
		return err
	}
	info, err := os.Stat(datadir)
	if err != nil {
		return err
	}
	log.Println("datadir", info.Name(), info.Mode())

	conn := api.NewConnectionTo("http://localhost:10000")

	spacename := "test5"
	err = createSpace(ctx, conn, spacename, datadir)
	if err != nil {
		return err
	}

	stream, err := conn.PostPacket(ctx, spacename, api.PacketPostRequest{Path: pcapfile})
	if err != nil {
		return err
	}
	for {
		iface, err := stream.Next()
		if err != nil {
			return err
		}
		if iface == nil {
			break
		}
		b, _ := json.Marshal(iface)
		log.Println(string(b))
	}

	return nil
}

func main() {
	pcapfile := flag.String("pcap", "", "pcap file")
	flag.Parse()

	if *pcapfile == "" {
		log.Fatal("no pcapfile specified")
	}

	err := ingest(context.Background(), *pcapfile)
	if err != nil {
		log.Fatal("ingest failed:", err)
	}
}
