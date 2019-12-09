using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace CTAPgetBLE
{
    public class ParseCTAP
    {
        protected CBORObject cborobj;
        public ParseCTAP(byte[] cobrbyte)
        {
            try {
                cborobj = CBORObject.DecodeFromBytes(cobrbyte, CBOREncodeOptions.Default);

                // debug
                var json = cborobj.ToJSONString();
                System.Diagnostics.Debug.WriteLine($"Recv: {json}");
            } catch (Exception ex) {
                System.Diagnostics.Debug.WriteLine($"CBOR DecordError:{ex.Message}");
            }
        }

        protected string[] getKeyValueAsStringArray(CBORObject obj)
        {
            var tmp = new List<string>();
            obj.Values.ToList().ForEach(x => tmp.Add(x.AsString()));
            return (tmp.ToArray());
        }

        protected int[] getKeyValueAsIntArray(CBORObject obj)
        {
            var tmp = new List<int>();
            obj.Values.ToList().ForEach(x => tmp.Add(x.AsInt32()));
            return (tmp.ToArray());
        }

        protected bool? getKeyValueAsBoolorNull(CBORObject obj, string key)
        {
            if (obj.ContainsKey(key)) {
                return (obj[key].AsBoolean());
            } else {
                return null;
            }
        }

    }

    public class ParseCTAPInfo : ParseCTAP
    {
        public enum OptionFlag
        {
            absent,                             // 未対応
            present_and_set_to_false,           // 未設定
            present_and_set_to_true,            // 設定済み
        };

        public string[] Versions { get; private set; }
        public string[] Extensions { get; private set; }
        public byte[] Aaguid { get; private set; }
        public OptionFlag Option_rk { get; private set; }
        public OptionFlag Option_up { get; private set; }
        public OptionFlag Option_plat { get; private set; }
        public OptionFlag Option_clientPin { get; private set; }
        public OptionFlag Option_uv { get; private set; }
        public int MaxMsgSize { get; private set; }
        public int[] PinProtocols { get; private set; }

        public ParseCTAPInfo(byte[] cobrbyte) : base(cobrbyte)
        {
            if (cborobj != null) {
                parse(cborobj);
            }
        }
        private void parse(CBORObject cbor)
        {
            foreach (var key in cbor.Keys) {
                var keyVal = key.AsByte();
                if (keyVal == 0x01) {
                    Versions = getKeyValueAsStringArray(cbor[key]);
                } else if (keyVal == 0x02) {
                    Extensions = getKeyValueAsStringArray(cbor[key]);
                } else if (keyVal == 0x03) {
                    Aaguid = cbor[key].GetByteString();
                } else if (keyVal == 0x04) {
                    Option_rk = getKeyValueAsOptionFlag(cbor[key], "rk");
                    Option_up = getKeyValueAsOptionFlag(cbor[key], "up");
                    Option_plat = getKeyValueAsOptionFlag(cbor[key], "plat");
                    Option_clientPin = getKeyValueAsOptionFlag(cbor[key], "clientPin");
                    Option_uv = getKeyValueAsOptionFlag(cbor[key], "uv");
                } else if (keyVal == 0x05) {
                    MaxMsgSize = cbor[key].AsInt16();
                } else if (keyVal == 0x06) {
                    PinProtocols = getKeyValueAsIntArray(cbor[key]);
                }
            }
        }

        private OptionFlag getKeyValueAsOptionFlag(CBORObject obj, string key)
        {
            bool? flag = getKeyValueAsBoolorNull(obj, key);
            if (flag == null) {
                return (OptionFlag.absent);
            } else if (flag == true) {
                return (OptionFlag.present_and_set_to_true);
            } else {
                return (OptionFlag.present_and_set_to_false);
            }
        }
    }

    public class ParseCTAPAssertion : ParseCTAP
    {
        public byte[] RpIdHash { get; set; }
        public bool Flags_UserPresentResult { get; set; }
        public bool Flags_UserVerifiedResult { get; set; }
        public bool Flags_AttestedCredentialDataIncluded { get; set; }
        public bool Flags_ExtensionDataIncluded { get; set; }

        public int SignCount { get; set; }
        public byte[] Aaguid { get; set; }

        public int NumberOfCredentials { get; set; }

        public byte[] Signature { get; set; }
        public byte[] User_Id { get; set; }
        public string User_Name { get; set; }
        public string User_DisplayName { get; set; }

        public byte[] AuthData { get; set; }

        public byte[] CredentialId { get; set; }

        public ParseCTAPAssertion(byte[] cobrbyte) : base(cobrbyte)
        {
            SignCount = 0;
            Aaguid = new byte[0];
            NumberOfCredentials = 0;
            Signature = new byte[0];
            User_Id = new byte[0];
            User_Name = "";
            User_DisplayName = "";
            CredentialId = new byte[0];

            if (cborobj != null) {
                parse(cborobj);
            }
        }

        private void parse(CBORObject cbor)
        {
            foreach (var key in cbor.Keys) {
                var keyVal = key.AsByte();
                if (keyVal == 0x01) {
                    // 0x01:credential
                    parseCredential(cbor[key]);
                } else if (keyVal == 0x02) {
                    parseAuthData(cbor[key].GetByteString());
                } else if (keyVal == 0x03) {
                    // 0x03:signature
                    Signature = cbor[key].GetByteString();
                } else if (keyVal == 0x04) {
                    parsePublicKeyCredentialUserEntity(cbor[key]);
                } else if (keyVal == 0x05) {
                    // 0x05:numberOfCredentials
                    NumberOfCredentials = cbor[key].AsUInt16();

                }
            }
        }

        private void parseAuthData(byte[] data)
        {
            int index = 0;

            // rpIdHash	(32)
            RpIdHash = data.Skip(index).Take(32).ToArray();
            index = index + 32;

            // flags(1)
            {
                byte flags = data[index];
                index++;
                Flags_UserPresentResult = Common.GetBit(flags, 0);
                Flags_UserVerifiedResult = Common.GetBit(flags, 2);
                Flags_AttestedCredentialDataIncluded = Common.GetBit(flags, 6);
                Flags_ExtensionDataIncluded = Common.GetBit(flags, 7);
            }

            // signCount(4)
            {
                SignCount = Common.ToInt32(data, index, true);
                index = index + 4;
            }

            // aaguid	16
            Aaguid = data.Skip(index).Take(16).ToArray();
            index = index + 16;

            AuthData = data;
        }

        private void parsePublicKeyCredentialUserEntity(CBORObject cbor)
        {
            foreach (var key in cbor.Keys) {
                var keyVal = key.AsString();
                if (keyVal == "id") {
                    User_Id = cbor[key].GetByteString();
                } else if (keyVal == "name") {
                    User_Name = cbor[key].AsString();
                } else if (keyVal == "displayName") {
                    User_DisplayName = cbor[key].AsString();
                }
            }

        }

        private void parseCredential(CBORObject cbor)
        {
            foreach (var key in cbor.Keys) {
                var keyVal = key.AsString();
                if (keyVal == "id") {
                    CredentialId = cbor[key].GetByteString();
                } else if (keyVal == "type") {
                }
            }

        }

    }

}
