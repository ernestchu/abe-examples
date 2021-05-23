T1 = cpabe
T2 = kpabe

all: clean $(T1).cpp $(T2).cpp
	g++ -std=c++11 $(T1).cpp -o $(T1) -lopenabe
	g++ -std=c++11 $(T2).cpp -o $(T2) -lopenabe

clean:
	rm -f $(T1) $(T2)
