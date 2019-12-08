using System;
using System.Windows;
using System.Collections.Generic;
using System.Linq;
using Windows.Devices.Enumeration;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Windows.Threading;
//using PeterO.Cbor;
using CTAPget;
using System.Configuration;

namespace CTAPgetBLE
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        enum UVType
        {
            PIN,
            UV,
        }

        private string ArgUserID = "";
        private UVType AuthUV = UVType.PIN;
        private string Password = "";
        private Notify notify;

        private BluetoothLEAdvertisementWatcher AdvWatcher;
        private BluetoothLEDevice BleDevice;
        private GattDeviceService Service_Fido;
        private GattCharacteristic Characteristic_Send;
        private GattCharacteristic Characteristic_Receive;
        private List<byte> ReceveData;
        private ReceiveData ReceiveBuff;

        public MainWindow()
        {
            string[] args = Environment.GetCommandLineArgs();
            if (args.Length > 1) {
                ArgUserID = args[1].Trim();
            }

            {
                bool enableNotify = false;
                if (ConfigurationManager.AppSettings["EnableNotify"] == "1") {
                    enableNotify = true;
                }
                notify = new Notify(enableNotify);
            }

            InitializeComponent();

            init();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            scan();
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            {
                if (Service_Fido != null) {
                    Service_Fido.Dispose();
                    addLog("FIDO Service Disposed");
                }

                if (BleDevice != null) {
                    BleDevice.Dispose();
                    addLog("BLE Device Disposed");
                }
            }

            // パスワードが求まっていない場合はここで通知する
            if (!string.IsNullOrEmpty(this.ArgUserID)) {
                if (string.IsNullOrEmpty(this.Password)) {
                    var result = this.notify.Send("");
                }
            }

            // save config
            {
                Configuration config = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                if (AuthUV == UVType.PIN) {
                    config.AppSettings.Settings["SelectUV"].Value = "0";
                } else {
                    config.AppSettings.Settings["SelectUV"].Value = "1";
                }
                config.Save();
            }
        }

        private void init()
        {
            this.textTitle.Text = ArgUserID;
            this.textMessage1.Text = "";
            this.textMessage2.Text = "";
            this.textMessage3.Text = "";
            this.textPIN.Clear();
            this.textPIN.Visibility = Visibility.Hidden;
            this.buttonLogin.Visibility = Visibility.Hidden;
            this.imageUV.Visibility = Visibility.Hidden;
        }

        private bool scan()
        {
            this.AdvWatcher = new BluetoothLEAdvertisementWatcher();

            // インターバルがゼロのままだと、CPU負荷が高くなりますので、適切な間隔(SDK サンプルでは 1秒)に指定しないと、アプリの動作に支障をきたすことになります。
            this.AdvWatcher.SignalStrengthFilter.SamplingInterval = TimeSpan.FromMilliseconds(1000);

            // rssi >= -60のときスキャンする
            //this.advWatcher.SignalStrengthFilter.InRangeThresholdInDBm = -60;

            // パッシブスキャン/アクティブスキャン
            // スキャン応答のアドバタイズを併せて受信する場合＝BluetoothLEScanningMode.Active
            // ActiveにするとBluetoothLEAdvertisementType.ScanResponseが取れるようになる。（スキャンレスポンスとは追加情報のこと）
            // ※電力消費量が大きくなり、またバックグラウンド モードでは使用できなくなるらしい
            //this.advWatcher.ScanningMode = BluetoothLEScanningMode.Active;
            this.AdvWatcher.ScanningMode = BluetoothLEScanningMode.Passive;

            // アドバタイズパケットの受信イベント
            this.AdvWatcher.Received += this.Watcher_Received;

            // スキャン開始
            this.AdvWatcher.Start();

            this.textMessage1.Text = "BLE FIDOキーをONにしてください";

            return true;
        }

        private async Task<bool> sendCommand(byte[] command)
        {
            bool ret = false;
            try {
                if (command == null) {
                    return (ret);
                }

                // log
                addLog($"send Command...");
                addLog($"{BitConverter.ToString(command)}");

                ReceveData = new List<byte>();

                var result = await Characteristic_Send.WriteValueAsync(command.AsBuffer(), GattWriteOption.WriteWithResponse);
                if (result != GattCommunicationStatus.Success) {
                    // error
                    return (false);
                }
                ret = true;
            } catch (Exception ex) {
                addLog($"Exception...{ex.Message})");
            }
            return (ret);
        }

        private async Task<bool> sendInfo()
        {
            try {
                var cmd = new byte[4];

                // Command identifier
                cmd[0] = 0x83;      // MSG

                // High part of data length
                cmd[1] = 0x00;

                // Low part of data length
                cmd[2] = 0x01;

                // Data (s is equal to the length)
                cmd[3] = 0x04;

                var result = await sendCommand(cmd);

            } catch (Exception ex) {
                Console.WriteLine($"Exception...{ex.Message})");
            }
            return true;
        }

        private async void Watcher_Received(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
        {
            await this.Dispatcher.InvokeAsync(() => {
                this.CheckArgs(args);
            });
        }

        public async void CheckArgs(BluetoothLEAdvertisementReceivedEventArgs args)
        {
            Console.WriteLine("★Scan");

            // FIDOサービスを検索
            var fidoServiceUuid = new Guid("0000fffd-0000-1000-8000-00805f9b34fb");
            if (args.Advertisement.ServiceUuids.Contains(fidoServiceUuid) == false) {
                return;
            }

            // 発見
            this.AdvWatcher.Stop();

            // connect
            {
                addLog("Conncect FIDO Device");
                BleDevice = await BluetoothLEDevice.FromBluetoothAddressAsync(args.BluetoothAddress);
                //DebugMethods.OutputLog(BleDevice);
            }

            // FIDOのサービスをGET
            {
                addLog("Connect FIDO Service");
                var services = await BleDevice.GetGattServicesForUuidAsync(fidoServiceUuid);
                if (services.Services.Count <= 0) {
                    // サービス無し
                    addLog("Error Connect FIDO Service");
                    return;
                }
                Service_Fido = services.Services.First();
            }

            // Characteristicアクセス
            // - コマンド送信ハンドラ設定
            // - 応答受信ハンドラ設定
            {
                // FIDO Service Revision(Read)
                //await DebugMethods.OutputLog(Service_Fido, GattCharacteristicUuids.SoftwareRevisionString);

                // FIDO Control Point Length(Read-2byte)
                //await DebugMethods.OutputLog(Service_Fido, new Guid("F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB"));

                // FIDO Service Revision Bitfield(Read/Write-1+byte)
                //await DebugMethods.OutputLog(Service_Fido, new Guid("F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB"));

                // FIDO Status(Notiry) 受信データ
                {
                    var characteristics = await Service_Fido.GetCharacteristicsForUuidAsync(new Guid("F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB"));
                    if (characteristics.Characteristics.Count > 0) {
                        this.Characteristic_Receive = characteristics.Characteristics.First();
                        if (this.Characteristic_Receive == null) {
                            Console.WriteLine("Characteristicに接続できない...");
                        } else {
                            if (this.Characteristic_Receive.CharacteristicProperties.HasFlag(GattCharacteristicProperties.Notify)) {
                                // イベントハンドラ追加
                                this.Characteristic_Receive.ValueChanged += characteristicChanged_OnReceiveFromDevice;

                                // これで有効になる
                                await this.Characteristic_Receive.WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue.Notify);
                            }
                        }
                    }
                }

                // FIDO Control Point(Write) 送信データ
                {
                    var characteristics = await Service_Fido.GetCharacteristicsForUuidAsync(new Guid("F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB"));
                    if (characteristics.Characteristics.Count > 0) {
                        this.Characteristic_Send = characteristics.Characteristics.First();
                        if (this.Characteristic_Send == null) {
                            Console.WriteLine("Characteristicに接続できない...");
                        }
                    }
                }

                addLog("BLE FIDOキーと接続しました!");
            }

            // PEND
            var result = await sendInfo();

        }

        private void buttonLogin_Click(object sender, RoutedEventArgs e)
        {

        }

        private void RadioButtonPIN_Checked(object sender, RoutedEventArgs e)
        {

        }

        private void RadioButtonUV_Checked(object sender, RoutedEventArgs e)
        {

        }

        private void addLog(string message)
        {
            Console.WriteLine($"{message}");
            var ignored = this.Dispatcher.BeginInvoke(DispatcherPriority.Normal, (Action)(() => {
                textMessage2.Text = message;
            }));
        }

        protected void characteristicChanged_OnReceiveFromDevice(GattCharacteristic sender, GattValueChangedEventArgs eventArgs)
        {
            addLog($"characteristicChanged...");
            addLog($"- Length={eventArgs.CharacteristicValue.Length}");
            if (eventArgs.CharacteristicValue.Length <= 0) {
                return;
            }

            byte[] data = new byte[eventArgs.CharacteristicValue.Length];
            Windows.Storage.Streams.DataReader.FromBuffer(eventArgs.CharacteristicValue).ReadBytes(data);

            // for log
            {
                var tmp = BitConverter.ToString(data);
                addLog($"- Data...");
                addLog($"{tmp}");
            }

            // parse
            {
                // [0] STAT
                if (data[0] == 0x81) {
                    addLog($"PING");
                } else if (data[0] == 0x82) {
                    addLog($"KEEPALIVE");
                } else if (data[0] == 0x83) {
                    addLog($"MSG");
                    ReceiveBuff = new ReceiveData(data);

                    // [1] HLEN
                    // [2] LLEN
                    // [3-] DATA
                    var buff = data.Skip(3).Take(data.Length).ToArray();
                    // 最初の1byteは応答ステータスで2byteからCBORデータ
                    var cbor = buff.Skip(1).Take(buff.Length).ToArray();

                    // 受信バッファに追加
                    //ReceveData.AddRange(cbor.ToList());

                } else if (data[0] == 0xbe) {
                    // CANCEL
                    addLog($"CANCEL");
                } else if (data[0] == 0xbf) {
                    // ERROR
                    addLog($"ERROR");
                } else {
                    ReceiveBuff.Add(data);
                    /*
                    // データの続き
                    var buff = data;
                    // 最初の1byteは応答ステータスで2byteからCBORデータ
                    var cbor = buff.Skip(1).Take(buff.Length).ToArray();
                    // 受信バッファに追加
                    ReceveData.AddRange(cbor.ToList());
                    */
                }
            }

            {
                if(this.ReceiveBuff.IsReceiveComplete()) {
                    //
                    int a = 0;
                }

            }

            return;
        }

    }
}
