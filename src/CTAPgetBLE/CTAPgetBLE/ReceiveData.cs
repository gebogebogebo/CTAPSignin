using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CTAPgetBLE
{
    public class ReceiveData
    {
        private int dataSize=0;
        private List<byte> cbor;

        public ReceiveData(byte[] data)
        {
            cbor = new List<byte>();

            // [1] HLEN
            // [2] LLEN
            {
                var len = new byte[2];
                len[0] = data[2];
                len[1] = data[1];

                dataSize = BitConverter.ToInt16(len, 0) - 1;
            }

            // [3-] DATA
            var buff = data.Skip(3).Take(data.Length).ToArray();
            // 最初の1byteは応答ステータスで2byteからCBORデータ
            var tmp = buff.Skip(1).Take(buff.Length).ToArray();
            // 受信バッファに追加
            cbor.AddRange(tmp.ToList());
        }
        
        public void Add(byte[] data)
        {
            // 最初の1byteは応答ステータスで2byteからCBORデータ
            var tmp = data.Skip(1).Take(data.Length).ToArray();
            // 受信バッファに追加
            cbor.AddRange(tmp.ToList());
        }

        public bool IsReceiveComplete()
        {
            if (cbor.Count == dataSize) {
                return true;
            } else {
                return false;
            }
        }
    }
}
