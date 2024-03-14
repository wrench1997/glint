package crawler

import "glint/logger"

func (tab *Tab) WatchEventSubmit() {
	var (
		b  bool
		bq bool
	)

	for {
		select {
		case b = <-tab.Eventchanel.ButtonCheckUrl:
			tab.lock.Lock()
			if b {
				tab.Eventchanel.EventInfo["Button"] = true
				tab.Eventchanel.ButtonRep <- "checkButton"
			} else {
				tab.Eventchanel.EventInfo["Button"] = false
				tab.Eventchanel.ButtonRep <- "checkButton"
			}
			tab.lock.Unlock()
		case b = <-tab.Eventchanel.SubmitCheckUrl:
			tab.lock.Lock()
			if b {
				tab.Eventchanel.EventInfo["Submit"] = true
				tab.Eventchanel.SubmitRep <- "checkSubmit"
			} else {
				tab.Eventchanel.EventInfo["Submit"] = false
				tab.Eventchanel.SubmitRep <- "checkSubmit"
			}
			tab.lock.Unlock()
		case <-tab.Eventchanel.exit:
			bq = true
			// if _, ok := <-tab.Eventchanel.SubmitCheckUrl; !ok {
			// 	close(tab.Eventchanel.SubmitCheckUrl)
			// }
			// if _, ok := <-tab.Eventchanel.ButtonCheckUrl; !ok {
			// 	close(tab.Eventchanel.ButtonCheckUrl)
			// }
			// if _, ok := <-tab.Eventchanel.ButtonRep; !ok {
			// 	close(tab.Eventchanel.ButtonRep)
			// }
			// if _, ok := <-tab.Eventchanel.SubmitRep; !ok {
			// 	close(tab.Eventchanel.SubmitRep)
			// }
			goto end
		}

	end:
		if bq {
			logger.Debug("crawler watching thread exit")
			break
		}
	}
}
