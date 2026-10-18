module example.com/parse

go 1.27.2

// held: v2 drops the streaming API
replace example.com/held => example.com/held v1.2.0

replace example.com/local => ./local

// this comment is separated from the block by a blank line

require (
	example.com/direct v1.0.0
	example.com/trailing v1.1.0 // v1.2 breaks the wire format
	// a comment line directly above the line
	example.com/above v0.3.0
	example.com/dep v1.0.0 // indirect
	example.com/why v2.0.0 // indirect; pinned by the parent
	"example.com/quoted" v0.1.0
)

require example.com/single v0.9.0

replace example.com/one v1.0.0 => example.com/one v1.0.1

tool (
	example.com/tool
)

exclude example.com/bad v0.0.1
