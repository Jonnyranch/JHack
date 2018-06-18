using System;
using System.Windows.Forms;

namespace filebrowser
{
    static class Program
    {
        /// <summary>
        /// Der Haupteinstiegspunkt für die Anwendung.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
#if DEBUG
            //Application.Run(new Client());
            Application.Run(new Login());

            //test 2
#else
            Application.Run(new Login());
#endif

        }
    }
}
