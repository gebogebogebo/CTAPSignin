using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace CTAPgetBLE
{
    public class SendData
    {
        private const int PACKETSIZE = 151;

        public byte[] CreateInfo()
        {
            var cmd = new byte[4];

            // Command identifier
            cmd[0] = 0x83;      // MSG

            // High part of data length
            cmd[1] = 0x00;

            // Low part of data length
            cmd[2] = 0x01;

            // Data (s is equal to the length)
            cmd[3] = 0x04;

            return (cmd);
        }

        public List<byte[]> CreateGetAssertion(string rpid)
        {
            var commands = new List<byte[]>();

            try {
                // param
                string RpId = rpid;
                byte[] ClientDataHash = System.Text.Encoding.ASCII.GetBytes("this is challenge");
                byte[] AllowList_CredentialId = null;
                bool Option_up = true;
                bool Option_uv = true;

                var cbor = CBORObject.NewMap();

                // 0x01 : rpid
                cbor.Add(0x01, RpId);

                // 0x02 : clientDataHash
                cbor.Add(0x02, ClientDataHash);

                // 0x03 : allowList
                if (AllowList_CredentialId != null) {
                    var pubKeyCredParams = CBORObject.NewMap();
                    pubKeyCredParams.Add("type", "public-key");
                    pubKeyCredParams.Add("id", AllowList_CredentialId);
                    cbor.Add(0x03, CBORObject.NewArray().Add(pubKeyCredParams));
                }

                // 0x05 : options
                {
                    var opt = CBORObject.NewMap();
                    opt.Add("up", Option_up);
                    opt.Add("uv", Option_uv);
                    cbor.Add(0x05, opt);
                }

                /*
                if (PinAuth != null) {
                    // pinAuth(0x06)
                    cbor.Add(0x06, PinAuth);
                    // 0x07:pinProtocol
                    cbor.Add(0x07, 1);
                }
                */

                var payloadb = cbor.EncodeToBytes();

                var cmd = new List<byte>();

                // Command identifier
                cmd.Add(0x83);      // MSG

                // High part of data length
                cmd.Add(0x00);

                // Low part of data length
                cmd.Add((byte)(payloadb.Length + 1));

                // パケット2つに分割送信する
                // fidoControlPointLength=0x9B(155byte)
                // なので、1パケット155になるように分割する
                // ※155より小さい値で分割してもエラーになる
                // ※このサンプルでは固定値にしていますが、fidoControlPointLengthが155とは限らないので注意
                var send1 = payloadb.Skip(0).Take(PACKETSIZE).ToArray();
                var send2 = payloadb.Skip(PACKETSIZE).Take(100).ToArray();

                // Frame 0
                cmd.Add(0x02);          // authenticatorGetAssertion (0x02)
                cmd.AddRange(send1);
                commands.Add(cmd.ToArray());

                // Frame 1
                if(send2.Length > 0) {
                    cmd.Clear();
                    cmd.Add(0x00);
                    cmd.AddRange(send2);
                    commands.Add(cmd.ToArray());
                }

            } catch (Exception ex) {
                Console.WriteLine($"Exception...{ex.Message})");
            }
            return (commands);
        }
    }
}
