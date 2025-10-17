package main

import (
    "fmt"
    "os"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Fprintln(os.Stderr, "Usage: urwarden <URL>")
        os.Exit(2)
    }

    url := os.Args[1]
    fmt.Printf("{\"input_url\": \"%s\", \"score\": 0, \"label\": \"benign\"}\n", url)
}
