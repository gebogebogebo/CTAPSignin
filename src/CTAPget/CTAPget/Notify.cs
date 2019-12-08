using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.IO.Pipes;

namespace CTAPget
{
    public class Notify
    {
        private const string PIPENAME = "ctapgetpipe";
        private const int TIMEOUTMS = 3000;
        private bool enableNotify = false;

        public Notify(bool enable)
        {
            this.enableNotify = enable;
        }

        public async Task<bool> SendAsync(string password)
        {
            var result = await Task<bool>.Run(() => {
                return (this.Send(password));
            });

            return result;
        }

        public bool Send(string password)
        {
            try {
                if (this.enableNotify == false) {
                    return true;
                }

                // パイプサーバ作成
                Func<NamedPipeServerStream> createpipe = delegate () {
                    var ps = new PipeSecurity();
                    ps.AddAccessRule(new PipeAccessRule("Everyone", PipeAccessRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
                    return new NamedPipeServerStream(PIPENAME, PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous, 1024, 1024, ps);
                };

                using (var server = createpipe()) {
                    var aresult = server.BeginWaitForConnection((ar) => { Console.WriteLine("Client Connect."); }, null);

                    var connected = aresult.AsyncWaitHandle.WaitOne(TIMEOUTMS);
                    if (!connected) {
                        Console.WriteLine("Timeout.");
                        return false;
                    }
                    server.EndWaitForConnection(aresult);

                    var streamWriter = new StreamWriter(server);
                    streamWriter.Write(password);
                    streamWriter.Flush();
                    server.WaitForPipeDrain();
                }

            } catch (Exception ex) {
                return false;
            }
            return true;
        }

    }
}
