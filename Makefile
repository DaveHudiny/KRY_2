CC = g++
CFLAGS  = -fsanitize=address -fsanitize=leak
TARGET = kry
 
all: $(TARGET)
 
$(TARGET): $(TARGET).cpp $(TARGET).hpp
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).cpp $(TARGET).hpp
 
clean:
	$(RM) $(TARGET)

run:
	./$(TARGET)