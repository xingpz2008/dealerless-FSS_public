//
// Created by  邢鹏志 on 2023/2/5.
//
#include<iostream>
#include"aes.h"

int main(){
    auto start = std::chrono::high_resolution_clock::now();
    int repeat = 200;
    long long key = 25;
    long long word[2] = {4, 9};
    long long after[2] = {0, 0};
    AES ak(key);
    for (int i = 0; i < repeat; i++){
        ak.ecbEncTwoBlocks(word, after);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "Total time = " << duration << ", Avg Time = " << duration/repeat << std::endl;
    return 0;
}