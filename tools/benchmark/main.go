package main

import (
	"flag"
	"fmt"
	"net/http"
	"sync"
	"time"
)

func main() {
	url := flag.String("url", "http://localhost:8080", "URL to benchmark")
	concurrency := flag.Int("c", 10, "Number of concurrent requests")
	requests := flag.Int("n", 1000, "Total number of requests")
	duration := flag.Duration("d", 0, "Duration of the test")
	flag.Parse()

	results := make(chan time.Duration, *requests)
	errors := make(chan error, *requests)
	var wg sync.WaitGroup

	start := time.Now()
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	if *duration > 0 {
		timer := time.NewTimer(*duration)
		go func() {
			<-timer.C
			fmt.Println("Duration reached, stopping...")
			*requests = 0
		}()
	}

	// Start workers
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < *requests / *concurrency; i++ {
				requestStart := time.Now()
				resp, err := client.Get(*url)
				if err != nil {
					errors <- err
					continue
				}
				resp.Body.Close()
				results <- time.Since(requestStart)
			}
		}()
	}

	// Wait for completion
	wg.Wait()
	close(results)
	close(errors)

	// Process results
	var total time.Duration
	var count int
	var min, max time.Duration
	errCount := 0

	for d := range results {
		if min == 0 || d < min {
			min = d
		}
		if d > max {
			max = d
		}
		total += d
		count++
	}

	for range errors {
		errCount++
	}

	// Print results
	fmt.Printf("\nBenchmark Results:\n")
	fmt.Printf("URL: %s\n", *url)
	fmt.Printf("Concurrency Level: %d\n", *concurrency)
	fmt.Printf("Time taken: %v\n", time.Since(start))
	fmt.Printf("Complete requests: %d\n", count)
	fmt.Printf("Failed requests: %d\n", errCount)
	fmt.Printf("Requests per second: %.2f\n", float64(count)/time.Since(start).Seconds())
	fmt.Printf("Mean latency: %v\n", total/time.Duration(count))
	fmt.Printf("Min latency: %v\n", min)
	fmt.Printf("Max latency: %v\n", max)
}
