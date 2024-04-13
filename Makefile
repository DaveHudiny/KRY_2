CC = g++
CFLAGS  = -fsanitize=address -fsanitize=leak
TARGET = kry
 
all: $(TARGET)
 
$(TARGET): $(TARGET).cpp
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).cpp
 
clean:
	$(RM) $(TARGET)

run:
	./$(TARGET)