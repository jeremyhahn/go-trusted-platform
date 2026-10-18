module example.com/app

go 1.27.2

replace example.com/gone => example.com/gone v0.4.1

require (
	example.com/current v1.4.0
	example.com/documented v1.2.0 // v1.3 removes the Foo API; unpin when bar adopts Baz
	github.com/jeremyhahn/go-latest v0.5.0-alpha
)
