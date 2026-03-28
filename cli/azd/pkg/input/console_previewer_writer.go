// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package input

// consolePreviewerWriter implements io.Writer and is used to wrap a progress log.
// Writes after the previewer is stopped are silently discarded. This is expected
// during parallel deploys where a sibling service may close the shared console
// previewer while another service's log stream is still active.
type consolePreviewerWriter struct {
	// holds the address of a previously created progressLog
	// when the referenced progressLog becomes nil, this component should write no more.
	previewer **progressLog
}

func (cp *consolePreviewerWriter) Write(logBytes []byte) (int, error) {
	writer := *cp.previewer
	if writer == nil {
		// Previewer was stopped — discard the write gracefully.
		// This can happen during parallel deploys when a sibling service
		// closes the shared console previewer while log streaming continues.
		return len(logBytes), nil
	}

	return writer.Write(logBytes)
}
