package vector

import "testing"

func BenchmarkMakeParameters1000(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = MakeParameters(1000)
	}
}
