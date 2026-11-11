module example.com/app

go 1.27.4

// forked to drop cgo; unpin when upstream merges the pure-Go build
replace example.com/forked => example.com/fork v1.0.0

replace example.com/gone => example.com/gone v0.4.1

replace example.com/sdk => ./sdk

require (
	example.com/current v1.4.0
	example.com/behind v1.2.0
	example.com/documented v1.2.0 // v1.3 removes the Foo API; unpin when bar adopts Baz
	example.com/pseudo v0.0.0-20250101000000-abcdefabcdef
	github.com/jeremyhahn/go-lib v0.3.0-alpha
	github.com/jeremyhahn/go-latest v0.5.0-alpha
	example.com/forked v1.0.0
	example.com/sdk v0.1.0
	example.com/dep v1.0.0 // indirect
)
