//
// Created by  邢鹏志 on 2023/2/5.
//
#include<iostream>
#include<cmath>
double AND_A_COMM = 0.0078125;
double AND_B_COMM = 3.8147e-6;
int AND_ROUND = 1;
int MUX2_ROUND = 2;

double MUX_COMM = 0.00391388;
double MUX2_COMM = 2 * MUX_COMM;

double MUX_LAN_TIME = 811; //microsec
double MUX2_LAN_TIME = 2 * MUX_LAN_TIME;
double AND_LAN_TIME = 2508; //microsec

double AES_TIME = 14420153 / pow(2, 32);

double Rec_u8 = sizeof(unsigned char)/((1.0 * (1ULL << 20)));
double Rec_block = sizeof(long long)/((1.0 * (1ULL << 20)));
double Rec_ge = (sizeof(int) + sizeof(long long))/((1.0 * (1ULL << 20)));
double Layer_wise_Rec_COMM = Rec_block + Rec_u8 * 2;

int Rec_ROUND = 1;



int main(void){
    int Bin = 16;
    int Bout = 16;
    double DPF_TIME = AES_TIME * pow(2, Bin) + Bin * (MUX2_LAN_TIME) + (MUX2_LAN_TIME + 2 * AND_LAN_TIME);
    double DPF_COMM = Bin * (Layer_wise_Rec_COMM + MUX2_COMM) + (AND_A_COMM + AND_B_COMM)/2 + MUX2_COMM + Rec_ge;
    int DPF_ROUND = (AND_ROUND + MUX2_ROUND + Rec_ROUND) + (Rec_ROUND + MUX2_ROUND) * Bin;
    double iDPF_TIME = AES_TIME * pow(2, Bin) + Bin * (MUX2_LAN_TIME) + Bin * (MUX2_LAN_TIME + 2 * AND_LAN_TIME);
    double iDPF_COMM = Bin * (Layer_wise_Rec_COMM + MUX2_COMM + (AND_A_COMM + AND_B_COMM)/2 + MUX2_COMM + Rec_ge);
    int iDPF_ROUND = (AND_ROUND + MUX2_ROUND + Rec_ROUND + Rec_ROUND + MUX2_ROUND) * Bin;
    double D_TIME = AES_TIME * Bin;
    double DPF_KEYSIZE = (sizeof(long long) * (1 + Bin) + (Bin * sizeof(unsigned char) * 2) + sizeof(int))/((1.0 * (1ULL << 20)));
    double iDPF_KEYSIZE = (sizeof(long long) * (1 + Bin) + (Bin * sizeof(unsigned char) * 2) + Bin * sizeof(int))/((1.0 * (1ULL << 20)));
    std::cout << "Settings: Bit len Input " << Bin << ", Output " << Bout << std::endl;
    std::cout << "DPF Communication: " << DPF_COMM << " MB in ~" << DPF_ROUND << " rounds within " << DPF_TIME/1000 << " ms." << std::endl;
    std::cout << "DCF Communication: " << iDPF_COMM << " MB in ~" << iDPF_ROUND << " rounds within " << iDPF_TIME/1000 << " ms." << std::endl;
    std::cout << "Trusted Dealer Overhead: " << D_TIME/1000 << " ms with " << 2 * iDPF_KEYSIZE << " MB transferred." << std::endl;
    return 0;
}