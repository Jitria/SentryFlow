package collector

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/5gsec/SentryFlow/config"
	"github.com/5gsec/SentryFlow/processor"
	"github.com/5gsec/SentryFlow/protobuf"
	"github.com/gin-gonic/gin"
)

func setupRouter() *gin.Engine {
	r := gin.Default()
	return r
}

func StartAPIServer() {
	gin := setupRouter()
	api := gin.Group("/api")
	{
		api.POST("/headers", showHeaders)
	}

	apiPort := fmt.Sprintf(":%v", config.GlobalConfig.WasmPort)

	gin.Run(apiPort)
}

func showHeaders(c *gin.Context) {
	data, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
		return
	}

	headersStr := string(data)

	headersMap := parseHeaders(headersStr)

	wasmLog := &protobuf.APILog{
		Id:             0,
		Authentication: headersMap["authorization"],
		Method:         headersMap["x-request-id"],
		Path:           headersMap["path"],
		SrcIP:          headersMap["authority"],
	}

	processor.InsertAPILog(wasmLog)
	c.JSON(http.StatusOK, gin.H{"message": "Headers received and processed"})
}

func parseHeaders(headersStr string) map[string]string {
	headers := strings.Split(headersStr, "\n")
	headersMap := make(map[string]string)

	for _, line := range headers {
		parts := strings.Split(line, ":")
		if parts[0] == "" {
			key := strings.TrimSpace(parts[1])
			value := strings.TrimSpace(parts[2])
			headersMap[key] = value
		} else {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headersMap[key] = value
		}
	}

	return headersMap
}

// @TODO: make below func, this is called by StopCollector
func ShutDownAPIServer() {

}
