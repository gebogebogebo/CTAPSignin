﻿using System;
using System.Collections.Generic;
using System.Linq;

namespace CTAPgetBLE
{
    public class Common
    {
        // 16進数文字列 => Byte配列
        public static byte[] HexStringToBytes(string str)
        {
            var bs = new List<byte>();
            for (int i = 0; i < str.Length / 2; i++) {
                bs.Add(Convert.ToByte(str.Substring(i * 2, 2), 16));
            }
            // "01-AB-EF" こういう"-"区切りを想定する場合は以下のようにする
            // var bs = str.Split('-').Select(hex => Convert.ToByte(hex, 16));
            return bs.ToArray();
        }

        // Byte配列 => 16進数文字列
        public static string BytesToHexString(byte[] bs)
        {
            var str = BitConverter.ToString(bs);
            // "-"がいらないなら消しておく
            str = str.Replace("-", string.Empty);
            return str;
        }

        public static int ToInt32(byte[] value, int startIndex, bool changeEndian = false)
        {
            byte[] sub = GetSubArray(value, startIndex, 4);
            if (changeEndian == true) {
                sub = sub.Reverse().ToArray();
            }
            return BitConverter.ToInt32(sub, 0);
        }

        public static int ToInt16(byte[] value, int startIndex, bool changeEndian = false)
        {
            byte[] sub = GetSubArray(value, startIndex, 2);
            if (changeEndian == true) {
                sub = sub.Reverse().ToArray();
            }
            return BitConverter.ToInt16(sub, 0);
        }

        // バイト配列から一部分を抜き出す
        private static byte[] GetSubArray(byte[] src, int startIndex, int count)
        {
            byte[] dst = new byte[count];
            Array.Copy(src, startIndex, dst, 0, count);
            return dst;
        }

        public static bool GetBit(byte bdata,int bit)
        {
            byte mask = 0x00;
            if( bit == 0) {
                mask = 0x01;
            } else if( bit == 1) {
                mask = 0x02;
            } else if (bit == 2) {
                mask = 0x04;
            } else if (bit == 3) {
                mask = 0x08;
            } else if (bit == 4) {
                mask = 0x10;
            } else if (bit == 5) {
                mask = 0x20;
            } else if (bit == 6) {
                mask = 0x40;
            } else if (bit == 7) {
                mask = 0x80;
            }
            if ((bdata & mask) == mask) {
                return true;
            } else {
                return false;
            }
        }

    }
}

