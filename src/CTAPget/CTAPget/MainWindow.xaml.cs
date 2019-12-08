using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using gebo.CTAP2.WebAuthnModokiDesktop;
using System.Configuration;

namespace CTAPget
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
        private gebo.CTAP2.DevParam devParam;
        private Notify notify;

        public MainWindow()
        {
            string[] args = Environment.GetCommandLineArgs();
            if (args.Length > 1) {
                ArgUserID = args[1].Trim();
            }

            devParam = gebo.CTAP2.DevParam.GetDefaultParams();

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

        private async void Window_Loaded(object sender2, RoutedEventArgs e2)
        {
            // read from config
            if (ConfigurationManager.AppSettings["TopMostWindow"] == "1") {
                this.Topmost = true;
            }
            if (ConfigurationManager.AppSettings["SelectUV"] == "1") {
                radioUV.IsChecked = true;
            }

            // PIN入力欄でENTER押したときの処理
            this.textPIN.KeyDown += (sender, e) => {
                if (e.Key != Key.Enter) { return; }
                string pin = this.textPIN.Password;
                if (string.IsNullOrEmpty(pin)) { return; }
                buttonLogin_Click(sender, e);
            };

            for (; ; ) {
                var ret = await this.start();
                if (ret) {
                    break;
                }
                // Keyがなくなったら戻る
                {
                    this.textMessage3.Text = "キーを取り外してやり直してください";
                    for (; ; ) {
                        if (poll() == 0) {
                            init();
                            break;
                        }
                        await Task.Delay(100);
                    }
                }
            }
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
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

        private async void buttonLogin_Click(object sender, RoutedEventArgs e)
        {
            var password = await authentication();
            var result = await checkPassword(password);
            return;
        }

        private void RadioButtonPIN_Checked(object sender, RoutedEventArgs e)
        {
            AuthUV = UVType.PIN;
        }
        private void RadioButtonUV_Checked(object sender, RoutedEventArgs e)
        {
            AuthUV = UVType.UV;
        }

        private void init()
        {
            this.textTitle.Text = ArgUserID;
            this.textMessage1.Text = "FIDO2セキュリティキーを接続してください";
            this.textMessage2.Text = "";
            this.textMessage3.Text = "";
            this.textPIN.Clear();
            this.textPIN.Visibility = Visibility.Hidden;
            this.buttonLogin.Visibility = Visibility.Hidden;
            this.imageUV.Visibility = Visibility.Hidden;
        }

        private int poll()
        {
            var hidstatus = gebo.CTAP2.WebAuthnModokiDesktop.Credentials.HidCheck(devParam.hidparams);
            if (hidstatus.isSuccess) {
                return 1;
            }

            var nfcstatus = gebo.CTAP2.WebAuthnModokiDesktop.Credentials.NfcCheck(devParam.nfcparams);
            if (nfcstatus.isSuccess) {
                return 2;
            }
            return 0;
        }

        private async Task<bool> start()
        {
            // step1
            bool step1 = false;
            InfoCommandStatus info = null;
            for (; ; ) {
                int devtype = poll();
                if (devtype != 0) {
                    info = await Credentials.Info(devParam);
                    if (info.isSuccess == false) {
                        // エラー
                        this.textMessage1.Text = $"Error キーを取り外してやり直してください";
                        this.textMessage2.Text = $"Error : {info.msg}";
                        break;
                    }
                    string devname = "";
                    if (devtype == 1) {
                        devname = info.HidInfo;
                    } else {
                        devname = info.NfcInfo;
                    }
                    this.textMessage2.Text = $"{devname} . PIN Retry = {info.PinRetryCount}";
                }
                if (info != null && info.isSuccess == true) {
                    // nextstep
                    step1 = true;
                    break;
                } else {
                    await Task.Delay(100);
                }
            }

            if (step1 == false) {
                return false;
            }

            // step2
            {
                if (AuthUV == UVType.PIN) {
                    if (info.AuthenticatorInfo.Option_clientPin != gebo.CTAP2.CTAPResponseInfo.OptionFlag.present_and_set_to_true) {
                        this.textMessage1.Text = $"Error このキーはPIN認証できません";
                        this.textMessage2.Text = $"Error : {info.AuthenticatorInfo.Option_clientPin}";
                        return false;
                    }

                    this.textMessage1.Text = "PINで認証してください";
                    this.textPIN.Visibility = Visibility.Visible;
                    this.textPIN.Focus();
                    this.buttonLogin.Visibility = Visibility.Visible;
                    return true;
                } else if (AuthUV == UVType.UV) {
                    if (info.AuthenticatorInfo.Option_uv != gebo.CTAP2.CTAPResponseInfo.OptionFlag.present_and_set_to_true) {
                        this.textMessage1.Text = $"Error このキーは生体認証できません";
                        this.textMessage2.Text = $"Error : {info.AuthenticatorInfo.Option_uv}";
                        return false;
                    }

                    this.textMessage1.Text = "指紋で認証してください";
                    this.imageUV.Visibility = Visibility.Visible;

                    var password = await authentication();
                    var result = await checkPassword(password);
                    return result;
                }
            }

            return false;
        }

        private async Task<bool> checkPassword(string password)
        {
            if (string.IsNullOrEmpty(password)) {
                // 認証NG
                return false;
            }
            this.textTitle.Text = "Authenticate";
            this.textMessage1.Text = "...";
            this.Password = password;
            var result = await this.notify.SendAsync(this.Password);

            Application.Current.Shutdown();

            return true;
        }

        private async Task<string> authentication()
        {
            try {
                this.textPIN.IsEnabled = false;
                this.buttonLogin.IsEnabled = false;

                var info = await Credentials.Info(devParam);
                if (info.isSuccess == false) {
                    this.textMessage1.Text = $"Error:デバイスが認識できませんでした";
                    return "";
                }

                string pin = this.textPIN.Password;

                if (AuthUV == UVType.PIN) {
                    if (string.IsNullOrEmpty(pin)) {
                        return "";
                    }
                }

                GetCommandStatus result = null;
                string rpid = ArgUserID;
                byte[] challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");

                this.textMessage2.Text = "Authenticate...";

                {
                    var credentialid = new byte[0];
                    string requireUserPresence = "false";       // UPは常に無効
                    string userVerification = "discouraged";    // UV無し
                    if (AuthUV == UVType.UV) {
                        userVerification = "preferred";         // UV必須
                    }
                    string json =
                       "{" +
                            string.Format($"timeout : 10000,") +
                            string.Format($"challenge:[{string.Join(",", challenge)}],") +
                            string.Format($"rpId : '{rpid}',") +
                           @"allowCredentials : [{" +
                               string.Format($"id : [{string.Join(",", credentialid)}],") +
                               string.Format($"type : 'public-key',") +
                           @"}]," +
                           string.Format($"requireUserPresence : '{requireUserPresence}',") +
                           string.Format($"userVerification : '{userVerification}',") +
                        "}";

                    result = await Credentials.Get(devParam, json, pin);
                }
                if (result.isSuccess == false) {
                    // error
                    info = await Credentials.Info(devParam);
                    this.textMessage1.Text = $"Error:PINリトライ {info.PinRetryCount}";
                    this.textMessage2.Text = result.msg;
                    return "";
                }
                // 最低限のチェック
                if (result.assertions.Count > 0 && result.assertions[0].Flags_UserVerifiedResult == true) {
                    string password = System.Text.Encoding.ASCII.GetString(result.assertions[0].User_Id);
                    return password;
                } else {
                    return "";
                }
            } finally {
                this.textPIN.Clear();
                this.textPIN.IsEnabled = true;
                this.buttonLogin.IsEnabled = true;
                Keyboard.Focus(this.textPIN);
            }
        }

    }
}
