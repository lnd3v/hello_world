all:
	rm target/debug/hello_world
	cargo build
	target/debug/hello_world	
