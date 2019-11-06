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

package otel

import (
	"context"
)

type commonMetric struct {
	instrument Instrument
}

type commonHandle struct {
	handle Handle
}

func (m commonMetric) acquireCommonHandle(labels LabelSet) commonHandle {
	return newCommonHandle(m.instrument.AcquireHandle(labels))
}

func (m commonMetric) float64Measurement(value float64) Measurement {
	return newMeasurement(m.instrument, NewFloat64Number(value))
}

func (m commonMetric) int64Measurement(value int64) Measurement {
	return newMeasurement(m.instrument, NewInt64Number(value))
}

func (m commonMetric) recordOne(ctx context.Context, number Number, labels LabelSet) {
	m.instrument.RecordOne(ctx, number, labels)
}

func (m commonMetric) Impl() Instrument {
	return m.instrument
}

func (h commonHandle) recordOne(ctx context.Context, number Number) {
	h.handle.RecordOne(ctx, number)
}

func (h commonHandle) Release() {
	h.handle.Release()
}

func newCommonMetric(instrument Instrument) commonMetric {
	return commonMetric{
		instrument: instrument,
	}
}

func newCommonHandle(handle Handle) commonHandle {
	return commonHandle{
		handle: handle,
	}
}

func newMeasurement(instrument Instrument, number Number) Measurement {
	return Measurement{
		instrument: instrument,
		number:     number,
	}
}