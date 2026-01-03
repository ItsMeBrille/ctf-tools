package main

import("bytes"; "fmt"; "io"; "net/http"; "sync")

func main() {
	// URL and payload
	numRequests := 2
	url := "https://challenge.com/submit"
	payload := []byte(`{"data": "true"}`)

	// WaitGroup to wait for all requests
	var wg sync.WaitGroup

	// Launch the requests concurrently
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		
		// Request
		defer wg.Done()
		resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		defer resp.Body.Close()

		// Response
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Response: %s", body)
	}
}