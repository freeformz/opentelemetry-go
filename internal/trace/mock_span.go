// Copyright 2019, OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trace

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"

	"go.opentelemetry.io/otel"
	apitrace "go.opentelemetry.io/otel/api/trace"
)

// MockSpan is a mock span used in association with MockTracer for testing purpose only.
type MockSpan struct {
	sc     otel.SpanContext
	tracer apitrace.Tracer
}

var _ apitrace.Span = (*MockSpan)(nil)

// SpanContext returns associated otel.SpanContext. If the receiver is nil it returns
// an empty otel.SpanContext
func (ms *MockSpan) SpanContext() otel.SpanContext {
	if ms == nil {
		otel.EmptySpanContext()
	}
	return ms.sc
}

// IsRecording always returns false for MockSpan.
func (ms *MockSpan) IsRecording() bool {
	return false
}

// SetStatus does nothing.
func (ms *MockSpan) SetStatus(status codes.Code) {
}

// SetError does nothing.
func (ms *MockSpan) SetError(v bool) {
}

// SetAttribute does nothing.
func (ms *MockSpan) SetAttribute(attribute otel.KeyValue) {
}

// SetAttributes does nothing.
func (ms *MockSpan) SetAttributes(attributes ...otel.KeyValue) {
}

// End does nothing.
func (ms *MockSpan) End(options ...apitrace.EndOption) {
}

// SetName does nothing.
func (ms *MockSpan) SetName(name string) {
}

// Tracer returns MockTracer implementation of Tracer.
func (ms *MockSpan) Tracer() apitrace.Tracer {
	return ms.tracer
}

// AddEvent does nothing.
func (ms *MockSpan) AddEvent(ctx context.Context, msg string, attrs ...otel.KeyValue) {
}

// AddEvent does nothing.
func (ms *MockSpan) AddEventWithTimestamp(ctx context.Context, timestamp time.Time, msg string, attrs ...otel.KeyValue) {
}

// AddLink does nothing.
func (ms *MockSpan) AddLink(link apitrace.Link) {
}

// Link does nothing.
func (ms *MockSpan) Link(sc otel.SpanContext, attrs ...otel.KeyValue) {
}
