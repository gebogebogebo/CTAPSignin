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

        enum CommandType
        {
            unknown=0x00,
            authenticatorGetAssertion=0x02,
            authenticatorGetInfo =0x04,
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

        private CommandType SendedCommandType= CommandType.unknown;
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
            // read from config
            if (ConfigurationManager.AppSettings["TopMostWindow"] == "1") {
                this.Topmost = true;
            }
            if (ConfigurationManager.AppSettings["SelectUV"] == "1") {
                radioUV.IsChecked = true;
            }

            scan();
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            {
                if( AdvWatcher != null) {
                    this.AdvWatcher.Stop();
                }

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
                var senddata = new SendData();
                var cmd = senddata.CreateInfo();

                var result = await sendCommand(cmd);
                if(result) {
                    SendedCommandType = CommandType.authenticatorGetInfo;
                }

            } catch (Exception ex) {
                Console.WriteLine($"Exception...{ex.Message})");
            }
            return true;
        }

        private async Task<bool> sendGetAssertion()
        {
            bool success = true;
            try {
                var senddata = new SendData();
                var sendcommands = senddata.CreateGetAssertion(ArgUserID);

                foreach(var cmd in sendcommands) {
                    success = await sendCommand(cmd);
                    if (success == false) {
                        break;
                    }
                }
                if(success) {
                    SendedCommandType = CommandType.authenticatorGetAssertion;
                }
            } catch (Exception ex) {
                Console.WriteLine($"Exception...{ex.Message})");
            }
            return success;
        }

        private async void Watcher_Received(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
        {
            await this.Dispatcher.InvokeAsync(() => {
                this.CheckArgs(args);
            });
        }

        public async void CheckArgs(BluetoothLEAdvertisementReceivedEventArgs args)
        {
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
                            addLog("Characteristicに接続できない");
                            return;
                        } else {
                            if (this.Characteristic_Receive.CharacteristicProperties.HasFlag(GattCharacteristicProperties.Notify)) {
                                // イベントハンドラ追加
                                this.Characteristic_Receive.ValueChanged += characteristicChanged_OnReceiveFromDevice;

                                // これで有効になる
                                await this.Characteristic_Receive.WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue.Notify);
                            } else {
                                addLog("Characteristicに接続できない");
                                return;
                            }
                        }
                    } else {
                        addLog("Characteristicに接続できない");
                        return;
                    }
                }

                // FIDO Control Point(Write) 送信データ
                {
                    var characteristics = await Service_Fido.GetCharacteristicsForUuidAsync(new Guid("F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB"));
                    if (characteristics.Characteristics.Count > 0) {
                        this.Characteristic_Send = characteristics.Characteristics.First();
                        if (this.Characteristic_Send == null) {
                            addLog("Characteristicに接続できない");
                            return;
                        }
                    } else {
                        addLog("Characteristicに接続できない");
                        return;
                    }
                }
            }

            addLog("BLE FIDOキーと接続しました!");
            var result = await sendInfo();
            //var result = await sendGetAssertion();
        }

        private void buttonLogin_Click(object sender, RoutedEventArgs e)
        {

        }

        private void RadioButtonPIN_Checked(object sender, RoutedEventArgs e)
        {
            AuthUV = UVType.PIN;
        }

        private void RadioButtonUV_Checked(object sender, RoutedEventArgs e)
        {
            AuthUV = UVType.UV;
        }

        private void addLog(string message)
        {
            Console.WriteLine($"{message}");
            var ignored = this.Dispatcher.BeginInvoke(DispatcherPriority.Normal, (Action)(() => {
                textMessage2.Text = message;
            }));
        }

        protected async void characteristicChanged_OnReceiveFromDevice(GattCharacteristic sender, GattValueChangedEventArgs eventArgs)
        {
            if (eventArgs.CharacteristicValue.Length <= 0) {
                return;
            }

            byte[] data = new byte[eventArgs.CharacteristicValue.Length];
            Windows.Storage.Streams.DataReader.FromBuffer(eventArgs.CharacteristicValue).ReadBytes(data);

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
                } else if (data[0] == 0xbe) {
                    // CANCEL
                    addLog($"CANCEL");
                } else if (data[0] == 0xbf) {
                    // ERROR
                    addLog($"ERROR");
                } else {
                    addLog($"next MSG?");
                    ReceiveBuff.Add(data);
                }
            }

            // 受信完了チェック
            if( ReceiveBuff != null) {
                if (this.ReceiveBuff.IsReceiveComplete()) {
                    var cborbyte = ReceiveBuff.Get();
                    var cmdtype = SendedCommandType;

                    SendedCommandType = CommandType.unknown;
                    this.ReceiveBuff.Clear();

                    // parse
                    if (cmdtype == CommandType.authenticatorGetInfo) {
                        var info = new ParseCTAPInfo(cborbyte);
                        if( info.Option_uv == ParseCTAPInfo.OptionFlag.present_and_set_to_true) {
                            // ここで指紋認証
                            var ignored = this.Dispatcher.BeginInvoke(DispatcherPriority.Normal, (Action)(() => {
                                this.textMessage1.Text = "指紋で認証してください";
                                this.imageUV.Visibility = Visibility.Visible;
                            }));

                            var result = await sendGetAssertion();
                        }
                    }else if (cmdtype == CommandType.authenticatorGetAssertion) {
                        var assertion = new ParseCTAPAssertion(cborbyte);
                        if (assertion.Flags_UserVerifiedResult) {
                            Password = System.Text.Encoding.ASCII.GetString(assertion.User_Id);

                            addLog($"Authenticate Success");

                            var ignored = this.Dispatcher.BeginInvoke(DispatcherPriority.Normal, (Action)(async() => {
                                this.textTitle.Text = "Authenticate";
                                this.textMessage1.Text = "...";
                                var result = await this.notify.SendAsync(this.Password);

                                Application.Current.Shutdown();
                            }));
                        }
                    }
                }
            }

            return;
        }

    }
}
