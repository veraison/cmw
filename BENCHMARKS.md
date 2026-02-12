# CMW Benchmarks

This file contains comprehensive benchmark tests for the CMW (Conceptual Message Wrappers) library performance.

## Running Benchmarks

### All Benchmarks
```bash
go test -bench=. -benchmem
```

### Specific Benchmark Categories

#### Marshaling Benchmarks
```bash
# All marshaling benchmarks
go test -bench="BenchmarkCMW_Marshal" -benchmem

# JSON marshaling only
go test -bench="BenchmarkCMW_MarshalJSON" -benchmem

# CBOR marshaling only 
go test -bench="BenchmarkCMW_MarshalCBOR" -benchmem
```

#### Unmarshaling Benchmarks
```bash
# All unmarshaling benchmarks
go test -bench="BenchmarkCMW_Unmarshal" -benchmem

# JSON unmarshaling only
go test -bench="BenchmarkCMW_UnmarshalJSON" -benchmem

# CBOR unmarshaling only
go test -bench="BenchmarkCMW_UnmarshalCBOR" -benchmem
```

#### X.509 Extension Benchmarks
```bash
# All X.509 extension operations
go test -bench="BenchmarkCMW_.*X509" -benchmem

# Encoding only
go test -bench="BenchmarkCMW_EncodeX509" -benchmem

# Decoding only  
go test -bench="BenchmarkCMW_DecodeX509" -benchmem
```

#### Data Size Comparisons
```bash
# Small data benchmarks
go test -bench=".*Small.*" -benchmem

# Medium data benchmarks
go test -bench=".*Medium.*" -benchmem

# Large data benchmarks
go test -bench=".*Large.*" -benchmem

# Collection benchmarks
go test -bench=".*Collection.*" -benchmem
```

#### Format-Specific Benchmarks
```bash
# CBOR Tag format benchmarks
go test -bench=".*Tag.*" -benchmem

# Auto-detection benchmarks
go test -bench="BenchmarkCMW_Deserialize" -benchmem

# Format sniffing benchmarks
go test -bench="BenchmarkSniff" -benchmem
```

### Advanced Options

#### Multiple Runs for Statistical Accuracy
```bash
go test -bench=. -benchmem -count=5
```

#### CPU Profiling
```bash
go test -bench=. -benchmem -cpuprofile=cpu.prof
```

#### Memory Profiling
```bash
go test -bench=. -benchmem -memprofile=mem.prof
```

#### Long-Running Benchmarks
```bash
go test -bench=. -benchmem -benchtime=10s
```

## Benchmark Data Sizes

The benchmarks test with different data sizes to understand performance characteristics:

- **Small**: ~15 bytes - Typical for simple attestation tokens
- **Medium**: ~1KB - Typical for complex attestation evidence  
- **Large**: ~100KB - Large attestation bundles or collections
- **Simple Collection**: 2 items - Basic collection structure
- **Complex Collection**: 50 nested items - Realistic nested attestation data

## Performance Insights

Based on the benchmark results:

1. **CBOR vs JSON**: CBOR is generally faster and uses less memory than JSON
2. **CBOR Tag Format**: Much faster than CBOR record format for monads
3. **Collections**: Performance scales reasonably with collection size
4. **X.509 Extensions**: CBOR encoding is faster than JSON for extensions
5. **Auto-detection**: Small overhead for format detection

## Adding New Benchmarks

When adding new benchmarks:

1. Follow the naming convention: `BenchmarkCMW_<Operation>_<DataType>_<Size>`
2. Include `b.ReportAllocs()` to track memory allocations
3. Use `b.ResetTimer()` after setup code
4. Handle errors appropriately with `b.Fatal(err)`
5. Create realistic test data that represents actual use cases

Example:
```go
func BenchmarkCMW_NewOperation_TestData(b *testing.B) {
    // Setup code here
    testData := setupTestData()
    
    b.ReportAllocs()
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        result, err := cmw.NewOperation(testData)
        if err != nil {
            b.Fatal(err)
        }
        _ = result // Prevent compiler optimization
    }
}
```