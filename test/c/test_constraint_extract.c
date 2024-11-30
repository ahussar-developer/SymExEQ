#include <stdio.h>

int simple_function(int x, int y) {
     int result = x+y;

    // Logic for i = 0
    if (x > 0) {
        result += 2;
    } else {
        result -= 1;
    }
    if (y == 0) {
        result += 10;
    }

    return result;
}

int main() {
    int x = 3;  // Hardcoded for testing but treated symbolically in angr
    int y = 2;

    int result = simple_function(x, y);
    //printf("Result: %d\n", result);

    return 0;
}
