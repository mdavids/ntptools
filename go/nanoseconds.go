package main

import (
        "fmt"
        "time"
)

func main() {
        for i := 0; i < 10; i++ {
                t := time.Now()
                fmt.Printf("%d\n", t.Nanosecond())
                time.Sleep(10 * time.Millisecond)
        }
}

//
// Altijd drie '000' aan het einde op MacOS
// Maar niet op Linux
// 
