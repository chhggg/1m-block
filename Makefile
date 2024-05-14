all: 1m-block

1m-block: main.cpp
	g++ -o 1m-block main.cpp -lnetfilter_queue

clean:
	rm -f 1m-block