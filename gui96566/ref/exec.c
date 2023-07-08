#include "quartz.h"
#include "quartz.hpp"
#include <stdio.h>

#include <bitset>
#include <iostream>

int main()
{
    int r = 0;
    // unsigned char sk[SECRETKEY_BYTES];
    unsigned long long sklen = 0;
    unsigned char pk[PUBLICKEY_BYTES];
    unsigned long long pklen = 0;

    unsigned char sm[SIGNATURE_BYTES];
    unsigned long long smlen = SIGNATURE_BYTES;

    unsigned char m[SHORTHASH_BYTES];
    unsigned long long mlen = SHORTHASH_BYTES;

    for (int i = 0; i < SHORTHASH_BYTES; i++)
    {
        m[i] = i;
    }

    // keypair(sk, &sklen, pk, &pklen);
    // for (int i = 0; i < sklen; i++)
    // {
    //     printf("%d, ", sk[i]);
    // }
    unsigned char sk[] = {201, 206, 42, 170, 217, 196, 21, 190, 1, 203, 67, 4, 47, 214, 238, 232, 21, 65, 2, 129, 135, 101, 97, 250, 124, 166, 19, 102, 98, 182, 158, 105, 105, 83, 252, 186, 114, 159, 129, 5, 205, 96, 113, 244, 101, 225, 166, 142, 62, 132, 171, 31, 73, 236, 207, 37, 113, 201, 75, 40, 206, 39, 58, 152, 117, 210, 167, 236, 79, 86, 118, 157, 234, 240, 126, 44, 100, 134, 255, 49, 129, 173, 235, 235, 97, 44, 253, 83, 254, 81, 195, 226, 155, 189, 103, 165, 191, 157, 13, 93, 233, 170, 140, 254, 126, 81, 78, 140, 50, 141, 189, 213, 249, 171, 124, 121, 140, 251, 106, 117, 199, 161, 91, 35, 164, 13, 60, 116, 2, 16, 244, 99, 178, 17, 237, 0, 114, 144, 22, 152, 236, 50, 243, 61, 1, 132, 77, 95, 240, 145, 0, 214, 16, 66, 139, 79, 103, 123, 207, 223, 153, 172, 80, 38, 91, 222, 23, 254, 159, 178, 142, 107, 212, 211, 152, 94, 10, 229, 97, 207, 3, 212, 209, 134, 188, 242, 167, 225, 13, 251, 190, 2, 155, 69, 191, 12, 171, 3, 14, 214, 213, 164, 152, 54, 1, 20, 214, 40, 229, 149, 242, 165, 214, 254, 246, 215, 125, 245, 62, 122, 197, 183, 22, 162, 142, 160, 33, 150, 46, 160, 45, 83, 175, 1, 2, 116, 198, 177, 185, 230, 99, 67, 201, 133, 138, 109, 31, 54, 112, 103, 151, 104, 222, 56, 12, 173, 86, 117, 137, 60, 26, 131, 43, 26, 33, 115, 27, 151, 1, 67, 7, 9, 13, 61, 216, 65, 253, 224, 139, 50, 22, 188, 194, 152, 161, 212, 164, 92, 227, 46, 207, 116, 210, 175, 146, 48, 210, 232, 152, 97, 75, 23, 53, 44, 97, 231, 213, 132, 85, 98, 209, 78, 108, 237, 51, 155, 221, 251, 194, 98, 188, 215, 247, 126, 237, 124, 222, 74, 19, 22, 239, 191, 229, 83, 32, 83, 199, 1, 226, 52, 171, 133, 221, 189, 164, 205, 77, 90, 129, 26, 136, 252, 28, 207, 83, 202, 26, 45, 238, 183, 235, 43, 102, 68, 36, 228, 76, 19, 59, 201, 121, 70, 30, 98, 168, 182, 172, 225, 251, 93, 106, 25, 104, 185, 243, 220, 88, 150, 70, 4, 6, 243, 71, 86, 43, 88, 38, 70, 14, 88, 13, 141, 210, 203, 235, 21, 178, 90, 31, 38, 108, 48, 58, 87, 59, 245, 192, 250, 84, 132, 42, 173, 171, 38, 186, 200, 78, 145, 248, 57, 246, 145, 199, 215, 22, 156, 158, 72, 115, 185, 17, 250, 8, 98, 219, 114, 4, 215, 96, 248, 34, 119, 10, 202, 167, 78, 77, 207, 49, 16, 181, 166, 91, 92, 3, 220, 160, 188, 13, 183, 34, 2, 13, 237, 71, 14, 93, 247, 205, 231, 155, 146, 135, 164, 120, 14, 86, 91, 213, 53, 112, 72, 76, 237, 156, 13, 134, 228, 234, 53, 15, 199, 152, 222, 242, 151, 235, 57, 156, 181, 83, 144, 13, 177, 167, 127, 250, 222, 90, 128, 216, 143, 176, 133, 181, 220, 219, 107, 80, 66, 194, 147, 253, 109, 93, 47, 9, 162, 90, 101, 42, 23, 165, 52, 226, 9, 163, 37, 251, 143, 183, 63, 19, 110, 71, 125, 84, 77, 154, 82, 49, 179, 99, 20, 50, 49, 35, 75, 78, 78, 206, 230, 118, 219, 91, 255, 117, 102, 113, 186, 182, 127, 77, 246, 33, 64, 107, 92, 40, 98, 113, 130, 46, 240, 37, 208, 207, 177, 55, 146, 128, 53, 249, 200, 220, 198, 98, 63, 156, 238, 215, 86, 25, 127, 176, 92, 30, 212, 109, 204, 74, 175, 79, 135, 209, 224, 124, 224, 115, 210, 31, 47, 74, 199, 233, 173, 123, 46, 192, 45, 90, 104, 49, 174, 13, 36, 123, 168, 156, 10, 54, 134, 237, 42, 202, 250, 91, 86, 188, 220, 2, 141, 219, 139, 181, 165, 222, 83, 61, 203, 82, 148, 182, 170, 87, 74, 2, 241, 212, 126, 196, 22, 76, 160, 36, 6, 149, 247, 200, 128, 151, 216, 181, 38, 18, 72, 128, 134, 48, 85, 210, 117, 219, 238, 97, 3, 224, 153, 86, 151, 253, 13, 22, 32, 67, 194, 200, 8, 113, 118, 255, 158, 202, 149, 77, 2, 181, 68, 168, 233, 138, 205, 7, 217, 94, 148, 225, 23, 9, 202, 51, 19, 166, 46, 85, 106, 87, 25, 59, 38, 29, 235, 238, 241, 240, 76, 47, 51, 110, 120, 32, 162, 2, 169, 73, 103, 129, 165, 226, 66, 160, 254, 127, 179, 248, 98, 227, 192, 71, 188, 105, 217, 227, 95, 17, 82, 182, 219, 152, 164, 185, 59, 65, 169, 159, 125, 24, 208, 34, 193, 168, 71, 75, 227, 200, 239, 253, 177, 162, 252, 4, 22, 26, 157, 144, 238, 244, 98, 73, 208, 254, 102, 21, 5, 75, 121, 72, 206, 150, 170, 45, 188, 232, 204, 21, 94, 37, 31, 203, 141, 92, 26, 143, 248, 174, 237, 109, 108, 69, 212, 70, 146, 39, 168, 134, 125, 229, 15, 63, 120, 169, 62, 141, 87, 138, 91, 113, 46, 138, 9, 44, 88, 117, 68, 164, 166, 188, 70, 106, 167, 238, 118, 186, 173, 127, 172, 57, 240, 2, 124, 21, 87, 103, 172, 234, 72, 43, 181, 140, 203, 182, 214, 135, 207, 27, 196, 100, 196, 245, 59, 97, 152, 171, 86, 28, 228, 231, 21, 144, 102, 91, 92, 144, 84, 30, 190, 229, 183, 2, 131, 168, 199, 17, 16, 119, 199, 77, 110, 205, 86, 225, 110, 59, 229, 135, 4, 96, 27, 116, 213, 138, 128, 118, 114, 219, 129, 116, 201, 161, 39, 104, 77, 42, 160, 40, 247, 131, 17, 143, 100, 29, 51, 228, 169, 58, 187, 57, 23, 204, 191, 202, 33, 148, 115, 92, 20, 232, 223, 121, 43, 94, 151, 145, 167, 138, 59, 214, 94, 222, 21, 87, 146, 183, 205, 25, 251, 223, 150, 24, 233, 141, 208, 105, 23, 142, 91, 105, 82, 221, 224, 47, 131, 209, 159, 8, 129, 87, 122, 84, 177, 151, 229, 117, 173, 57, 91, 209, 160, 174, 196, 5, 27, 155, 194, 67, 56, 97, 47, 132, 162, 188, 99, 192, 198, 21, 74, 71, 159, 150, 37, 243, 95, 158, 49, 77, 243, 12, 91, 125, 200, 101, 220, 153, 43, 230, 223, 243, 55, 2, 126, 196, 192, 34, 187, 211, 29, 204, 65, 122, 53, 40, 207, 99, 39, 239, 226, 97, 42, 52, 200, 157, 167, 102, 69, 207, 138, 224, 223, 199, 116, 83, 45, 157, 67, 135, 59, 104, 119, 228, 226, 29, 97, 91, 215, 130, 20, 107, 84, 103, 50, 0, 221, 208, 48, 1, 94, 230, 188, 196, 104, 3, 220, 170, 125, 230, 35, 215, 249, 118, 191, 96, 89, 41, 61, 68, 88, 237, 42, 45, 36, 206, 190, 16, 174, 101, 7, 213, 8, 245, 204, 197, 207, 32, 1, 99, 61, 8, 107, 171, 236, 121, 178, 185, 156, 76, 14, 100, 101, 12, 12, 77, 242, 40, 45, 36, 168, 72, 55, 58, 206, 160, 69, 0, 210, 204, 106, 55, 20, 108, 124, 6, 232, 135, 119, 151, 35, 159, 104, 163, 85, 185, 102, 5, 112, 120, 94, 174, 51, 10, 152, 95, 18, 113, 83, 91, 3, 11, 254, 234, 5, 21, 31, 12, 79, 106, 33, 108, 32, 89, 65, 146, 78, 144, 200, 34, 204, 28, 49, 14, 162, 175, 159, 233, 155, 69, 182, 27, 27, 131, 205, 45, 179, 62, 91, 35, 54, 208, 8, 247, 193, 40, 72, 103, 166, 245, 242, 229, 224, 198, 184, 102, 69, 65, 35, 182, 81, 74, 86, 131, 41, 194, 160, 181, 119, 239, 73, 28, 71, 198, 127, 18, 190, 90, 20, 227, 176, 32, 96, 10, 51, 76, 102, 22, 38, 206, 188, 207, 51, 67, 217, 12, 24, 50, 20, 226, 4, 218, 26, 16, 92, 73, 170, 207, 13, 246, 61, 98, 54, 82, 55, 32, 226, 24, 136, 157, 141, 163, 11, 26, 82, 5, 146, 85, 246, 10, 153, 203, 18, 104, 180, 101, 45, 194, 136, 20, 112, 96, 123, 14, 239, 42, 150, 46, 56, 30, 110, 111, 59, 80, 208, 140, 130, 81, 63, 42, 235, 156, 30, 233, 249, 248, 146, 27, 171, 75, 48, 74, 202, 60, 141, 35, 231, 87, 223, 152, 61, 225, 57, 93, 114, 238, 52, 236, 19, 132, 86, 232, 81, 128, 215, 70, 223, 253, 193, 225, 82, 21, 39, 88, 15, 139, 51, 241, 149, 199, 74, 219, 3, 126, 23, 137, 5, 238, 26, 246, 179, 114, 255, 230, 173, 17, 95, 61, 49, 120, 77, 236, 32, 232, 24, 208, 45, 133, 94, 201, 18, 159, 115, 146, 181, 37, 86, 35, 202, 122, 7, 165, 45, 41, 119, 201, 134, 128, 190, 119, 159, 33, 150, 11, 241, 104, 52, 224, 230, 245, 230, 76, 2, 106, 236, 227, 1, 66, 182, 28, 202, 175, 83, 21, 154, 27, 251, 39, 161, 1, 186, 3, 19, 206, 134, 24, 205, 101, 37, 109, 250, 170, 130, 138, 123, 16, 37, 138, 48, 169, 249, 109, 156, 83, 182, 41, 184, 229, 59, 76, 53, 169, 78, 112, 94, 45, 28, 158, 53, 188, 96, 23, 130, 55, 254, 22, 115, 244, 76, 231, 81, 44, 13, 16, 7, 242, 45, 200, 19, 90, 7, 192, 180, 224, 224, 192, 44, 45, 139, 99, 74, 168, 189, 115, 176, 237, 122, 81, 183, 225, 12, 49, 123, 111, 199, 136, 182, 125, 176, 24, 22, 248, 20, 42, 183, 75, 180, 117, 65, 213, 57, 131, 178, 140, 181, 201, 5, 3, 185, 194, 217, 204, 121, 246, 230, 138, 237, 38, 129, 54, 107, 206, 230, 173, 228, 74, 246, 49, 49, 86, 161, 190, 38, 171, 167, 88, 160, 242, 96, 220, 34, 199, 103, 122, 23, 26, 224, 125, 114, 44, 4, 160, 151, 201, 38, 162, 70, 117, 16, 216, 46, 251, 62, 85, 183, 220, 231, 189, 24, 33, 49, 18, 72, 6, 71, 178, 136, 106, 179, 212, 46, 96, 108, 181, 41, 95, 182, 14, 116, 79, 38, 10, 94, 102, 20, 65, 135, 39, 46, 124, 188, 158, 65, 84, 14, 250, 46, 203, 69, 244, 37, 85, 109, 139, 105, 117, 16, 45, 156, 134, 168, 202, 199, 9, 68, 193, 235, 248, 219, 82, 140, 199, 50, 171, 100, 189, 63, 96, 11, 208, 114, 232, 162, 191, 193, 222, 230, 55, 201, 10, 69, 251, 120, 80, 177, 160, 115, 119, 52, 239, 242, 244, 1, 99, 186, 55, 233, 38, 53, 184, 39, 195, 82, 155, 69, 37, 73, 251, 101, 13, 239, 71, 141, 188, 80, 6, 202, 154, 25, 130, 177, 46, 88, 88, 32, 227, 188, 255, 202, 64, 195, 34, 221, 177, 119, 140, 108, 158, 34, 173, 240, 220, 29, 63, 21, 36, 204, 15, 52, 22, 150, 135, 134, 71, 29, 60, 203, 63, 10, 112, 215, 16, 37, 114, 83, 107, 60, 30, 20, 186, 33, 140, 36, 222, 84, 250, 171, 15, 214, 13, 173, 83, 204, 50, 12, 120, 147, 143, 148, 17, 233, 41, 11, 28, 1, 176, 12, 251, 248, 30, 239, 161, 251, 31, 197, 46, 35, 184, 145, 39, 117, 64, 244, 92, 230, 249, 127, 176, 204, 109, 11, 108, 18, 8, 140, 31, 38, 179, 67, 149, 176, 254, 122, 174, 239, 36, 11, 40, 1, 188, 150, 25, 23, 160, 148, 75, 42, 43, 0, 159, 103, 43, 219, 12, 161, 154, 96, 74, 202, 174, 156, 58, 120, 237, 102, 46, 97, 113, 237, 45, 90, 139, 71, 107, 44, 38, 249, 83, 215, 62, 250, 47, 133, 114, 253, 242, 61, 4, 112, 120, 160, 45, 104, 188, 123, 160, 161, 233, 254, 213, 18, 53, 53, 40, 1, 147, 10, 213, 156, 84, 220, 159, 171, 47, 158, 166, 77, 72, 41, 35, 22, 148, 179, 118, 138, 148, 3, 14, 2, 210, 255, 111, 160, 52, 251, 37, 215, 173, 154, 35, 151, 212, 159, 216, 39, 182, 8, 77, 63, 6, 143, 114, 3, 224, 239, 141, 72, 22, 46, 22, 37, 182, 73, 169, 56, 43, 10, 38, 72, 228, 90, 191, 168, 204, 150, 44, 132, 226, 62, 73, 163, 14, 119, 193, 34, 87, 165, 224, 118, 48, 195, 12, 5, 78, 221, 93, 239, 32, 157, 34, 125, 54, 23, 215, 37, 188, 60, 166, 73, 40, 93, 157, 44, 52, 146, 62, 139, 51, 234, 219, 231, 195, 158, 19, 244, 1, 48, 168, 248, 210, 28, 198, 212, 124, 181, 90, 47, 15, 120, 139, 44, 27, 82, 39, 107, 163, 75, 21, 243, 189, 113, 241, 40, 115, 226, 222, 14, 165, 169, 249, 181, 179, 131, 98, 230, 160, 255, 219, 224, 63, 212, 145, 26, 108, 178, 100, 190, 109, 1, 48, 80, 120, 50, 49, 216, 72, 75, 78, 62, 247, 172, 197, 0, 168, 109, 7, 80, 45, 195, 191, 110, 66, 187, 208, 14, 213, 97, 0, 44, 54, 72, 67, 223, 58, 214, 220, 241, 61, 149, 237, 89, 62, 221, 148, 201, 58, 61, 235, 177, 38, 227, 166, 239, 79, 47, 228, 214, 63, 200, 33, 4, 22, 175, 135, 19, 111, 66, 13, 76, 20, 23, 176, 20, 129, 156, 65, 218, 111, 130, 195, 24, 232, 68, 227, 195, 132, 212, 30, 141, 39, 163, 191, 170, 58, 100, 56, 172, 4, 56, 87, 65, 205, 117, 63, 117, 66, 50, 88, 230, 100, 146, 97, 136, 61, 189, 163, 90, 130, 140, 19, 43, 110, 241, 206, 96, 200, 119, 130, 8, 127, 117, 73, 20, 226, 238, 247, 12, 108, 214, 202, 51, 219, 208, 240, 170, 40, 2, 116, 175, 85, 227, 63, 102, 172, 92, 90, 27, 151, 39, 209, 153, 145, 217, 153, 109, 42, 128, 245, 107, 250, 245, 39, 153, 198, 124, 130, 186, 169, 196, 52, 109, 81, 26, 114, 59, 117, 208, 143, 187, 79, 123, 87, 191, 135, 200, 187, 81, 33, 98, 153, 172, 252, 9, 180, 100, 13, 91, 82, 236, 243, 10, 183, 172, 8, 139, 113, 51, 137, 70, 153, 100, 10, 161, 51, 142, 208, 4, 151, 26, 4, 39, 151, 128, 25, 212, 173, 43, 237, 106, 238, 31, 39, 131, 98, 59, 126, 219, 118, 254, 57, 5, 164, 50, 80, 218, 237, 103, 61, 222, 76, 227, 161, 11, 57, 159, 208, 149, 149, 4, 241, 75, 216, 32, 6, 56, 58, 113, 133, 16, 217, 45, 89, 255, 85, 20, 112, 71, 93, 39, 148, 137, 27, 11, 18, 185, 129, 244, 9, 43, 57, 60, 35, 135, 6, 176, 58, 156, 42, 140, 170, 226, 138, 118, 24, 51, 192, 215, 89, 186, 190, 50, 249, 118, 41, 80, 83, 55, 42, 1, 113, 89, 111, 100, 85, 114, 246, 105, 72, 145, 174, 216, 11, 153, 57, 17, 66, 243, 22, 171, 242, 146, 54, 117, 102, 132, 72, 149, 105, 17, 145, 17, 243, 119, 244, 55, 204, 225, 99, 195, 13, 48, 67, 10, 180, 22, 69, 112, 180, 127, 91, 126, 27, 217, 252, 17, 10, 240, 103, 137, 161, 104, 247, 221, 44, 53, 148, 251, 45, 218, 110, 94, 183, 175, 44, 130, 37, 111, 170, 38, 33, 9, 207, 234, 50, 55, 147, 141, 48, 245, 230, 77, 216, 168, 54, 40, 146, 127, 39, 151, 137, 57, 156, 112, 143, 238, 62, 86, 54, 255, 222, 46, 197, 81, 100, 217, 77, 72, 136, 247, 180, 68, 30, 167, 175, 29, 214, 77, 237, 27, 53, 82, 200, 8, 244, 45, 7, 160, 160, 176, 42, 46, 19, 173, 58, 244, 182, 17, 89, 29, 202, 226, 245, 52, 11, 51, 234, 69, 192, 138, 144, 13, 56, 142, 72, 76, 137, 144, 167, 236, 236, 163, 211, 222, 148, 8, 34, 29, 151, 37, 139, 67, 188, 250, 138, 214, 181, 113, 207, 88, 184, 76, 111, 192, 203, 60, 212, 47, 101, 244, 214, 83, 207, 152, 143, 242, 33, 52, 249, 38, 216, 63, 171, 121, 54, 102, 35, 79, 169, 173, 231, 110, 69, 108, 64, 195, 156, 6, 89, 195, 186, 104, 129, 119, 40, 27, 115, 22, 244, 214, 191, 210, 6, 150, 71, 202, 150, 37, 214, 254, 216, 241, 250, 38, 81, 228, 61, 48, 166, 160, 135, 144, 19, 223, 188, 173, 224, 116, 240, 75, 253, 112, 125, 60, 32, 255, 218, 69, 74, 238, 254, 26, 78, 92, 62, 132, 49, 86, 56, 24, 120, 253, 148, 123, 14, 23, 81, 239, 236, 21, 62, 29, 178, 56, 242, 181, 197, 173, 197, 55, 235, 228, 203, 47, 97, 215, 127, 85, 73, 108, 129, 181, 72, 250, 146, 186, 30, 134, 170, 86, 209, 63, 80, 8, 219, 32, 83, 134, 100, 17, 151, 55, 164, 117, 81, 74, 11, 103, 189, 119, 226, 64, 85, 20, 131, 175, 205, 251, 197, 43, 39, 119, 133, 232, 226, 151, 168, 44, 206, 180, 2, 111, 33, 136, 175, 125, 50, 174, 113, 144, 138, 6, 2, 140, 102, 84, 145, 232, 129, 1, 184, 158, 156, 40, 114, 159, 84, 204, 156, 25, 221, 78, 34, 199, 98, 185, 226, 49, 104, 202, 158, 137, 50, 93, 54, 127, 161, 140, 55, 20, 231, 2, 202, 156, 52, 165, 113, 8, 204, 223, 46, 52, 192, 62, 209, 150, 234, 210, 92, 102, 67, 34, 50, 238, 206, 241, 147, 84, 186, 182, 49, 171, 118, 54, 118, 1, 21, 50, 238, 57, 21, 128, 182, 190, 37, 190, 172, 192, 118, 10, 174, 119, 126, 200, 66, 233, 220, 205, 205, 12, 159, 244, 95, 240, 249, 114, 226, 22, 146, 200, 176, 185, 68, 205, 52, 187, 146, 100, 187, 3, 171, 99, 78, 149, 60, 122, 175, 132, 118, 83, 98, 56, 92, 242, 239, 252, 157, 157, 237, 192, 21, 230, 122, 107, 187, 30, 139, 18, 235, 243, 17, 233, 60, 40, 125, 187, 194, 98, 183, 47, 236, 232, 112, 217, 194, 50, 151, 76, 191, 26, 93, 148, 12, 187, 205, 53, 94, 204, 104, 174, 189, 91, 205, 248, 186, 132, 81, 144, 214, 99, 118, 162, 220, 148, 238, 135, 0, 196, 13, 221, 68, 67, 195, 38, 197, 10, 35, 243, 147, 145, 141, 135, 72, 63, 83, 171, 234, 190, 159, 122, 109, 85, 173, 11, 96, 40, 43, 176, 122, 207, 155, 84, 237, 99, 93, 12, 172, 246, 201, 247, 75, 231, 124, 171, 138, 136, 214, 193, 15, 209, 79, 146, 249, 121, 218, 11, 104, 173, 73, 196, 224, 182, 82, 108, 233, 229, 47, 58, 221, 1, 170, 1};
    sklen = 3175;

    // 0000000000000000000000000000000000000000000000000000011111001110 tmp
    // 0000000000000000000000000000000000000000000000000000011111001110 tail T
    // 0000000000000000000000000000000000000000000000000000101000001100 tmp
    // 0000000000000000000000000000000000000000011111001110101000001100 tail T
    // 0000000000000000000000000000000000000000000000000000000101100000 tmp
    // 0000000000000000000000000000011111001110101000001100000101100000 tail T
    // 0000000000000000000000000000000000000010100100100000000100011010 tail accu_mm (S)
    // 0001111100111010100000110000010110000010100100100000000100011010 tail SM
    // 0001111100111010100000110000010110000010100100100000000100011010 tail SM2
    // 01101100
    // 01001001
    // 00111011
    // 01011110
    // 11110000
    // 01011000
    // 10101000
    // 00000010
    // 00011010
    // 00000001
    // 10010010
    // 10000010
    // 00000101
    // 10000011
    // 00111010
    // 00011111
    // inverted is

    // zeros (2) | non aggregated X(12 *3 = 36)        |   aggregated S (90)
    // 00        011111001110101000001100000101100000  101001001000000001000110100000001010101000010110001111000001011110001110110100100101101100 hello??? 3175

    unsigned char sigma_s[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}; // 90 / 8 = 12
    unsigned char output_x[5];
    int res = 0; // 36 /8 = 5

    signatureofshorthash_mq(sm, &smlen, m, mlen, sk, sklen, NULL, output_x);
    std::cout << "============================================================ \n";
    res = hfev(sk, sklen, sigma_s, 12, output_x, 2);
    //  res = hfev(sk, sklen, sigma_s, 12, output_x, 2);
    //  res = hfev(sk, sklen, sigma_s, 12, output_x, 2);

    std::string result_inverted[smlen];

    for (int i = 0; i < smlen; i++)
    {
        // printf("%d, ", sm[i]);

        std::string binary = std::bitset<sizeof(char) * 8>(sm[i]).to_string(); // to binary
        std::cout << binary << "\n";
        result_inverted[smlen - i - 1] = binary;
    }

    std::cout << "inverted is \n";
    for (int i = 0; i < smlen; i++)
    {
        std::cout << result_inverted[i];
    }

    printf(" hello??? %d\n", sklen);

    // zeros (2) | non aggregated X(12 *3 = 36)        |   aggregated S (90) - inverted
    // for 96 5 6 6 3

    return 0;
}