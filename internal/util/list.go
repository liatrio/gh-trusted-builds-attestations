package util

func SplitList(strings []string, chunkSize int) [][]string {
	var chunks [][]string
	length := len(strings)

	for i := 0; i < length; i += chunkSize {
		end := i + chunkSize

		if end > length {
			end = length
		}

		chunks = append(chunks, strings[i:end])
	}

	return chunks
}
