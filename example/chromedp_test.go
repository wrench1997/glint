package mydemo

// func Test_Name(t *testing.T) {
// 	// create chrome instance
// 	ctx, cancel := chromedp.NewContext(
// 		context.Background(),
// 		chromedp.WithLogf(log.Printf),
// 	)

// 	defer cancel()

// 	// create a timeout
// 	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
// 	defer cancel()

// 	// navigate to a page, wait for an element, click
// 	var example string
// 	err := chromedp.Run(ctx,
// 		chromedp.Navigate(`https://www.baidu.com/`),
// 	)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	log.Printf("Go's time.After example:\n%s", example)
// }
