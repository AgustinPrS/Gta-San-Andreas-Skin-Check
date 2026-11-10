// Copyright © 2026 OtherClap.
// Sale or commercial redistribution is prohibited without written permission from OtherClap.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

[assembly: AssemblyTitle("SkinCheck")]
[assembly: AssemblyCompany("OtherClap")]
[assembly: AssemblyProduct("SkinCheck")]
[assembly: AssemblyDescription("Local static analysis of skins and executable files")]
[assembly: AssemblyCopyright("Copyright © 2026 OtherClap. Sale or commercial use prohibited without written permission.")]
[assembly: AssemblyVersion("1.2.0.0")]

namespace SkinCheck
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    internal sealed class ScanOptions
    {
        public bool ExecutionMarkers;
        public bool Commands;
        public bool ExecutableSignatures;
        public bool RenderWareStructure;
        public bool EmbeddedUrls;
        public bool Entropy;
        public bool NetworkIndicators;
        public bool PersistenceIndicators;
        public bool CredentialIndicators;
        public bool Authenticode;
        public bool MemoryInjection;
    }

    internal sealed class Finding
    {
        public string Key;
        public object[] Arguments;

        public Finding(string key, params object[] arguments)
        {
            Key = key;
            Arguments = arguments;
        }
    }

    internal sealed class FileResult
    {
        public string Path;
        public string Hash;
        public string Error;
        public string ErrorKey;
        public long Length;
        public int Score;
        public double Entropy;
        public bool HasEntropy;
        public bool IsPe;
        public bool IsRenderWareAsset;
        public bool NetworkScanPerformed;
        public List<Finding> Signals = new List<Finding>();
        public List<string> Urls = new List<string>();
        public List<string> Addresses = new List<string>();
    }

    internal static class LanguageCatalog
    {
        private static readonly Dictionary<string, string> Spanish = Make(new string[] {
            "window_title", "SkinCheck - analizador local de archivos",
            "subtitle", "Revisión estática local para skins, archivos .exe y otros archivos",
            "language", "Idioma:",
            "filter_group", "Filtros (marcá cuáles querés aplicar)",
            "filter_execution", "RCE / ejecución de comandos",
            "filter_commands", "Scripts, shells y consola",
            "filter_pe", "PE/ELF camuflado",
            "filter_rw", "Estructura DFF/TXD",
            "filter_urls", "Red, IP y URLs",
            "filter_entropy", "Ofuscación y entropía",
            "filter_persistence", "Persistencia",
            "filter_credentials", "Credenciales",
            "filter_signature", "Firma Authenticode",
            "filter_injection", "Inyección y memoria",
            "add", "Agregar archivos...",
            "remove", "Quitar",
            "clear", "Vaciar lista",
            "analyze", "Analizar lista",
            "vt", "Buscar hash en VirusTotal",
            "save", "Guardar informe...",
            "column_file", "Archivo",
            "column_path", "Ubicación",
            "column_result", "Resultado",
            "pending", "Pendiente",
            "intro", "Arrastrá archivos a la lista o elegilos con “Agregar archivos...”.\r\n\r\nSkinCheck solo lee los archivos: no los abre en el juego, no los ejecuta y no los sube a internet.\r\nUna alerta es un indicio para revisar, no una confirmación de infección.",
            "status_ready", "Listo. El análisis se realiza en esta PC.",
            "status_no_added", "No se agregaron archivos nuevos.",
            "status_added", "Agregados: {0}. No se ejecutó ningún archivo.",
            "status_removed", "Se quitó el archivo seleccionado de la lista.",
            "status_empty", "Lista vacía.",
            "status_analyzing", "Analizando archivos localmente...",
            "status_progress", "Revisados {0} de {1}...",
            "status_done", "Análisis terminado. Ningún archivo fue ejecutado ni subido.",
            "status_report_saved", "Informe guardado: {0}",
            "status_hash_opened", "Se abrió VirusTotal con el SHA-256. SkinCheck no subió el archivo.",
            "message_add_first", "Agregá uno o más archivos primero.",
            "message_select_vt", "Seleccioná un archivo que ya hayas analizado. Se enviará solo su hash, no el archivo.",
            "message_analyze_first", "Analizá primero el archivo seleccionado.",
            "message_open_error", "No se pudo abrir el enlace: {0}",
            "info_title", "SkinCheck",
            "dialog_open_title", "Elegí skins, programas u otros archivos",
            "dialog_all_files", "Todos los archivos (*.*)|*.*",
            "dialog_save_title", "Guardar informe de SkinCheck",
            "dialog_save_filter", "Informe de texto (*.txt)|*.txt",
            "dialog_save_name", "SkinCheck-informe.txt",
            "footer_copyright", "© 2026 OtherClap.",
            "footer_restriction", "No se permite vender ni comercializar este programa sin autorización escrita.",
            "link_site", "Sitio web",
            "link_github", "GitHub: skins seguras",
            "link_viewer", "Visor de skins",
            "link_discord", "Discord",
            "link_samp", "SAMP Hispano",
            "report_title", "SkinCheck - informe de análisis estático",
            "report_file", "Archivo: {0}",
            "report_size", "Tamaño: {0}",
            "report_hash", "SHA-256: {0}",
            "report_verdict", "Resultado: {0} (puntuación heurística {1}/100)",
            "report_indicators", "Indicadores:",
            "report_urls", "Direcciones encontradas (no son una prueba por sí solas):",
            "report_entropy", "Entropía: {0} bits por byte",
            "report_limit", "Límite: SkinCheck no ejecuta archivos y no consulta una base de firmas.",
            "report_no_clear", "“Sin señales claras” no significa que el archivo sea seguro.",
            "report_do_not_open", "No cargues archivos dudosos en el juego ni en un visor.",
            "report_error", "No se pudo analizar: {0}",
            "report_no_verdict", "No se generó un veredicto de seguridad.",
            "summary_high", "ALERTA ALTA ({0})",
            "summary_review", "Revisar ({0})",
            "summary_clear", "Sin señales claras ({0})",
            "summary_not_analyzed", "No analizado",
            "large_file", "El archivo supera el límite local de 100 MB.",
            "finding_pe_mismatch", "El archivo tiene un encabezado PE ejecutable, pero su extensión ({0}) no suele ser ejecutable.",
            "finding_embedded_pe", "Se encontró un ejecutable PE incrustado dentro del archivo, cerca del byte {0}.",
            "finding_exe_invalid", "La extensión parece ejecutable, pero no se reconoció un encabezado PE válido.",
            "finding_rw_short", "El archivo es demasiado corto para tener un encabezado DFF/TXD completo.",
            "finding_rw_id", "El identificador inicial no coincide con el encabezado habitual de {0}.",
            "finding_rw_size", "El tamaño declarado en el encabezado DFF/TXD no coincide con el tamaño del archivo.",
            "finding_rw_valid", "El encabezado y el tamaño general de {0} son coherentes.",
            "finding_execution", "Cadenas de APIs relacionadas con ejecución o carga: {0}.",
            "finding_injection", "APIs asociadas con memoria o inyección de procesos: {0}.",
            "finding_commands", "Cadenas de comandos o intérpretes: {0}.",
            "finding_urls", "Hay una o más direcciones web incrustadas. Una URL por sí sola no prueba que el archivo sea malicioso.",
            "finding_addresses", "Posibles IP o dominios incrustados (no son maliciosos por sí solos): {0}.",
            "finding_rce", "Primitivas de ejecución de comandos encontradas; esto no confirma una vulnerabilidad RCE: {0}.",
            "finding_network_apis", "Cadenas de APIs de red encontradas: {0}.",
            "finding_persistence", "Indicadores de persistencia o inicio automático: {0}.",
            "finding_credentials", "Indicadores relacionados con credenciales o datos sensibles: {0}.",
            "finding_script_encoding", "Indicadores de script, codificación u ofuscación: {0}.",
            "finding_embedded_elf", "Se encontró un encabezado ELF ejecutable incrustado cerca del byte {0}.",
            "finding_elf_mismatch", "El archivo contiene un ejecutable ELF con una extensión que no suele ser ejecutable ({0}).",
            "finding_signed", "Se encontró un certificado de firma. SkinCheck no valida la cadena de confianza.",
            "finding_unsigned", "No se encontró certificado Authenticode; muchos programas legítimos tampoco están firmados.",
            "finding_signature_error", "No se pudo consultar el certificado: {0}.",
            "report_addresses", "IPs y dominios candidatos (pueden ser falsos positivos):",
            "report_no_addresses", "No se encontraron IPs o dominios candidatos.",
            "report_rce_limit", "RCE depende de una vulnerabilidad y del programa que cargue el archivo; estas señales no prueban que se ejecute código.",
            "finding_entropy", "Entropía alta: puede indicar compresión o empaquetado; por sí sola no confirma malware.",
            "finding_none", "Los filtros seleccionados no encontraron indicadores claros.",
            "bytes", "{0} bytes",
            "error_title", "Error"
        });

        private static readonly Dictionary<string, string> English = Make(new string[] {
            "window_title", "SkinCheck - local file analyzer",
            "subtitle", "Local static review for skins, .exe files, and other files",
            "language", "Language:",
            "filter_group", "Filters (choose which ones to apply)",
            "filter_execution", "RCE / command execution",
            "filter_commands", "Scripts, shells and console",
            "filter_pe", "Hidden PE/ELF",
            "filter_rw", "DFF/TXD structure",
            "filter_urls", "Network, IPs and URLs",
            "filter_entropy", "Obfuscation and entropy",
            "filter_persistence", "Persistence",
            "filter_credentials", "Credentials",
            "filter_signature", "Authenticode signature",
            "filter_injection", "Memory and process injection",
            "add", "Add files...",
            "remove", "Remove",
            "clear", "Clear list",
            "analyze", "Analyze list",
            "vt", "Search hash on VirusTotal",
            "save", "Save report...",
            "column_file", "File",
            "column_path", "Location",
            "column_result", "Result",
            "pending", "Pending",
            "intro", "Drag files into the list or choose them with “Add files...”.\r\n\r\nSkinCheck only reads files: it does not open them in a game, execute them, or upload them.\r\nAn alert is an indicator to review, not confirmation of infection.",
            "status_ready", "Ready. Analysis runs on this PC.",
            "status_no_added", "No new files were added.",
            "status_added", "Added: {0}. No file was executed.",
            "status_removed", "The selected file was removed from the list.",
            "status_empty", "List cleared.",
            "status_analyzing", "Analyzing files locally...",
            "status_progress", "Reviewed {0} of {1}...",
            "status_done", "Analysis complete. No file was executed or uploaded.",
            "status_report_saved", "Report saved: {0}",
            "status_hash_opened", "VirusTotal opened with the SHA-256. SkinCheck did not upload the file.",
            "message_add_first", "Add one or more files first.",
            "message_select_vt", "Select a file you have already analyzed. Only its hash will be sent, not the file.",
            "message_analyze_first", "Analyze the selected file first.",
            "message_open_error", "Could not open the link: {0}",
            "info_title", "SkinCheck",
            "dialog_open_title", "Choose skins, programs, or other files",
            "dialog_all_files", "All files (*.*)|*.*",
            "dialog_save_title", "Save SkinCheck report",
            "dialog_save_filter", "Text report (*.txt)|*.txt",
            "dialog_save_name", "SkinCheck-report.txt",
            "footer_copyright", "© 2026 OtherClap.",
            "footer_restriction", "Sale or commercial use is prohibited without written permission.",
            "link_site", "Website",
            "link_github", "GitHub: safe skins",
            "link_viewer", "Skins viewer",
            "link_discord", "Discord",
            "link_samp", "SAMP Hispano",
            "report_title", "SkinCheck - static analysis report",
            "report_file", "File: {0}",
            "report_size", "Size: {0}",
            "report_hash", "SHA-256: {0}",
            "report_verdict", "Result: {0} (heuristic score {1}/100)",
            "report_indicators", "Indicators:",
            "report_urls", "Addresses found (not proof by themselves):",
            "report_entropy", "Entropy: {0} bits per byte",
            "report_limit", "Limit: SkinCheck does not execute files or check a signature database.",
            "report_no_clear", "“No clear indicators” does not mean the file is safe.",
            "report_do_not_open", "Do not load suspicious files into a game or viewer.",
            "report_error", "Could not analyze: {0}",
            "report_no_verdict", "No security verdict was generated.",
            "summary_high", "HIGH ALERT ({0})",
            "summary_review", "Review ({0})",
            "summary_clear", "No clear indicators ({0})",
            "summary_not_analyzed", "Not analyzed",
            "large_file", "The file exceeds the local 100 MB limit.",
            "finding_pe_mismatch", "The file has an executable PE header, but its extension ({0}) is not normally executable.",
            "finding_embedded_pe", "An executable PE was found embedded in the file near byte {0}.",
            "finding_exe_invalid", "The extension looks executable, but no valid PE header was recognized.",
            "finding_rw_short", "The file is too short to contain a complete DFF/TXD header.",
            "finding_rw_id", "The first identifier does not match the usual {0} header.",
            "finding_rw_size", "The size declared in the DFF/TXD header does not match the file size.",
            "finding_rw_valid", "The {0} header and overall size are consistent.",
            "finding_execution", "Execution or loading API strings: {0}.",
            "finding_injection", "Memory or process-injection API strings: {0}.",
            "finding_commands", "Command or interpreter strings: {0}.",
            "finding_urls", "One or more web addresses are embedded. A URL alone does not prove the file is malicious.",
            "finding_addresses", "Possible embedded IPs or domains (not malicious by themselves): {0}.",
            "finding_rce", "Command execution primitives were found; this does not confirm an RCE vulnerability: {0}.",
            "finding_network_apis", "Network API strings found: {0}.",
            "finding_persistence", "Persistence or auto-start indicators: {0}.",
            "finding_credentials", "Credential or sensitive-data indicators: {0}.",
            "finding_script_encoding", "Script, encoding, or obfuscation indicators: {0}.",
            "finding_embedded_elf", "An executable ELF header was found embedded near byte {0}.",
            "finding_elf_mismatch", "The file contains an ELF executable but has an extension that is not normally executable ({0}).",
            "finding_signed", "A signing certificate was found. SkinCheck does not validate its trust chain.",
            "finding_unsigned", "No Authenticode certificate was found; many legitimate programs are unsigned too.",
            "finding_signature_error", "Could not inspect the certificate: {0}.",
            "report_addresses", "Candidate IPs and domains (may be false positives):",
            "report_no_addresses", "No candidate IPs or domains were found.",
            "report_rce_limit", "RCE depends on a vulnerability and the program loading the file; these indicators do not prove code execution.",
            "finding_entropy", "High entropy may indicate compression or packing; by itself it does not confirm malware.",
            "finding_none", "The selected filters found no clear indicators.",
            "bytes", "{0} bytes",
            "error_title", "Error"
        });

        private static readonly Dictionary<string, string> Portuguese = Make(new string[] {
            "window_title", "SkinCheck - analisador local de arquivos",
            "subtitle", "Análise estática local de skins, arquivos .exe e outros arquivos",
            "language", "Idioma:",
            "filter_group", "Filtros (escolha quais aplicar)",
            "filter_execution", "RCE / execução de comandos",
            "filter_commands", "Scripts, shells e console",
            "filter_pe", "PE/ELF oculto",
            "filter_rw", "Estrutura DFF/TXD",
            "filter_urls", "Rede, IPs e URLs",
            "filter_entropy", "Ofuscação e entropia",
            "filter_persistence", "Persistência",
            "filter_credentials", "Credenciais",
            "filter_signature", "Assinatura Authenticode",
            "filter_injection", "Injeção e memória",
            "add", "Adicionar arquivos...",
            "remove", "Remover",
            "clear", "Limpar lista",
            "analyze", "Analisar lista",
            "vt", "Pesquisar hash no VirusTotal",
            "save", "Salvar relatório...",
            "column_file", "Arquivo",
            "column_path", "Localização",
            "column_result", "Resultado",
            "pending", "Pendente",
            "intro", "Arraste arquivos para a lista ou escolha-os em “Adicionar arquivos...”.\r\n\r\nO SkinCheck apenas lê os arquivos: não os abre em um jogo, não os executa e não os envia.\r\nUm alerta é um indício para revisão, não uma confirmação de infecção.",
            "status_ready", "Pronto. A análise é feita neste computador.",
            "status_no_added", "Nenhum arquivo novo foi adicionado.",
            "status_added", "Adicionados: {0}. Nenhum arquivo foi executado.",
            "status_removed", "O arquivo selecionado foi removido da lista.",
            "status_empty", "Lista limpa.",
            "status_analyzing", "Analisando arquivos localmente...",
            "status_progress", "Analisados {0} de {1}...",
            "status_done", "Análise concluída. Nenhum arquivo foi executado ou enviado.",
            "status_report_saved", "Relatório salvo: {0}",
            "status_hash_opened", "O VirusTotal foi aberto com o SHA-256. O SkinCheck não enviou o arquivo.",
            "message_add_first", "Adicione um ou mais arquivos primeiro.",
            "message_select_vt", "Selecione um arquivo já analisado. Somente o hash será enviado, não o arquivo.",
            "message_analyze_first", "Analise o arquivo selecionado primeiro.",
            "message_open_error", "Não foi possível abrir o link: {0}",
            "info_title", "SkinCheck",
            "dialog_open_title", "Escolha skins, programas ou outros arquivos",
            "dialog_all_files", "Todos os arquivos (*.*)|*.*",
            "dialog_save_title", "Salvar relatório do SkinCheck",
            "dialog_save_filter", "Relatório de texto (*.txt)|*.txt",
            "dialog_save_name", "SkinCheck-relatorio.txt",
            "footer_copyright", "© 2026 OtherClap.",
            "footer_restriction", "Venda ou uso comercial proibido sem autorização por escrito.",
            "link_site", "Site",
            "link_github", "GitHub: skins seguras",
            "link_viewer", "Visualizador de skins",
            "link_discord", "Discord",
            "link_samp", "SAMP Hispano",
            "report_title", "SkinCheck - relatório de análise estática",
            "report_file", "Arquivo: {0}",
            "report_size", "Tamanho: {0}",
            "report_hash", "SHA-256: {0}",
            "report_verdict", "Resultado: {0} (pontuação heurística {1}/100)",
            "report_indicators", "Indicadores:",
            "report_urls", "Endereços encontrados (não são prova por si só):",
            "report_entropy", "Entropia: {0} bits por byte",
            "report_limit", "Limite: o SkinCheck não executa arquivos nem consulta uma base de assinaturas.",
            "report_no_clear", "“Sem indícios claros” não significa que o arquivo seja seguro.",
            "report_do_not_open", "Não carregue arquivos suspeitos em um jogo ou visualizador.",
            "report_error", "Não foi possível analisar: {0}",
            "report_no_verdict", "Nenhum veredito de segurança foi gerado.",
            "summary_high", "ALERTA ALTO ({0})",
            "summary_review", "Revisar ({0})",
            "summary_clear", "Sem indícios claros ({0})",
            "summary_not_analyzed", "Não analisado",
            "large_file", "O arquivo excede o limite local de 100 MB.",
            "finding_pe_mismatch", "O arquivo tem um cabeçalho PE executável, mas a extensão ({0}) normalmente não é executável.",
            "finding_embedded_pe", "Um executável PE foi encontrado dentro do arquivo, perto do byte {0}.",
            "finding_exe_invalid", "A extensão parece executável, mas nenhum cabeçalho PE válido foi reconhecido.",
            "finding_rw_short", "O arquivo é curto demais para conter um cabeçalho DFF/TXD completo.",
            "finding_rw_id", "O identificador inicial não corresponde ao cabeçalho habitual de {0}.",
            "finding_rw_size", "O tamanho declarado no cabeçalho DFF/TXD não corresponde ao tamanho do arquivo.",
            "finding_rw_valid", "O cabeçalho e o tamanho geral de {0} são coerentes.",
            "finding_execution", "Strings de APIs relacionadas à execução ou carregamento: {0}.",
            "finding_injection", "APIs associadas à memória ou injeção de processos: {0}.",
            "finding_commands", "Strings de comandos ou interpretadores: {0}.",
            "finding_urls", "Há um ou mais endereços da web incorporados. Uma URL sozinha não prova que o arquivo seja malicioso.",
            "finding_addresses", "Possíveis IPs ou domínios incorporados (não são maliciosos por si só): {0}.",
            "finding_rce", "Foram encontradas primitivas de execução de comandos; isso não confirma uma vulnerabilidade RCE: {0}.",
            "finding_network_apis", "Strings de APIs de rede encontradas: {0}.",
            "finding_persistence", "Indicadores de persistência ou inicialização automática: {0}.",
            "finding_credentials", "Indicadores relacionados a credenciais ou dados sensíveis: {0}.",
            "finding_script_encoding", "Indicadores de script, codificação ou ofuscação: {0}.",
            "finding_embedded_elf", "Um cabeçalho ELF executável foi encontrado dentro do arquivo, perto do byte {0}.",
            "finding_elf_mismatch", "O arquivo contém um executável ELF, mas usa uma extensão que normalmente não é executável ({0}).",
            "finding_signed", "Foi encontrado um certificado de assinatura. O SkinCheck não valida a cadeia de confiança.",
            "finding_unsigned", "Nenhum certificado Authenticode foi encontrado; muitos programas legítimos também não têm assinatura.",
            "finding_signature_error", "Não foi possível consultar o certificado: {0}.",
            "report_addresses", "IPs e domínios candidatos (podem ser falsos positivos):",
            "report_no_addresses", "Nenhum IP ou domínio candidato foi encontrado.",
            "report_rce_limit", "RCE depende de uma vulnerabilidade e do programa que carrega o arquivo; estes indicadores não provam execução de código.",
            "finding_entropy", "Entropia alta pode indicar compactação ou empacotamento; sozinha, não confirma malware.",
            "finding_none", "Os filtros selecionados não encontraram indícios claros.",
            "bytes", "{0} bytes",
            "error_title", "Erro"
        });

        private static Dictionary<string, string> Make(string[] pairs)
        {
            Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.Ordinal);
            for (int i = 0; i + 1 < pairs.Length; i += 2)
                values[pairs[i]] = pairs[i + 1];
            return values;
        }

        public static string T(string language, string key, params object[] arguments)
        {
            Dictionary<string, string> values = Spanish;
            if (language == "en")
                values = English;
            else if (language == "pt-BR")
                values = Portuguese;
            string format;
            if (!values.TryGetValue(key, out format))
                format = key;
            if (arguments == null || arguments.Length == 0)
                return format;
            return String.Format(Culture(language), format, arguments);
        }

        public static CultureInfo Culture(string language)
        {
            if (language == "en")
                return CultureInfo.GetCultureInfo("en-US");
            if (language == "pt-BR")
                return CultureInfo.GetCultureInfo("pt-BR");
            return CultureInfo.GetCultureInfo("es-UY");
        }
    }

    internal sealed class MainForm : Form
    {
        private readonly ListView _files = new ListView();
        private readonly RichTextBox _report = new RichTextBox();
        private readonly Label _status = new Label();
        private readonly Label _subtitle = new Label();
        private readonly Label _languageLabel = new Label();
        private readonly Label _copyright = new Label();
        private readonly GroupBox _filterGroup = new GroupBox();
        private readonly Button _analyzeButton = new Button();
        private readonly Button _vtButton = new Button();
        private readonly Button _addButton = new Button();
        private readonly Button _removeButton = new Button();
        private readonly Button _clearButton = new Button();
        private readonly Button _saveButton = new Button();
        private readonly ComboBox _languageBox = new ComboBox();
        private readonly CheckBox _executionFilter = new CheckBox();
        private readonly CheckBox _commandsFilter = new CheckBox();
        private readonly CheckBox _peFilter = new CheckBox();
        private readonly CheckBox _rwFilter = new CheckBox();
        private readonly CheckBox _urlFilter = new CheckBox();
        private readonly CheckBox _entropyFilter = new CheckBox();
        private readonly CheckBox _persistenceFilter = new CheckBox();
        private readonly CheckBox _credentialFilter = new CheckBox();
        private readonly CheckBox _signatureFilter = new CheckBox();
        private readonly CheckBox _injectionFilter = new CheckBox();
        private readonly LinkLabel[] _links = new LinkLabel[5];
        private readonly Dictionary<string, FileResult> _results =
            new Dictionary<string, FileResult>(StringComparer.OrdinalIgnoreCase);
        private readonly string[] _linkUrls = new string[] {
            "https://www.otherclap.net",
            "https://github.com/AgustinPrS/Skins-de-GTA-San-Andreas-0.3DL",
            "https://skins.otherclap.net",
            "https://discord.gg/FSwJ63ugXy",
            "https://discord.gg/uJje6ybhZs"
        };
        private string _language = "es";

        public MainForm()
        {
            Text = LanguageCatalog.T(_language, "window_title");
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(900, 650);
            Size = new Size(1120, 780);
            BackColor = Color.FromArgb(246, 248, 251);
            Font = new Font("Segoe UI", 9F);
            LoadEmbeddedBranding();
            BuildInterface();
            ApplyLanguage();
        }

        private void LoadEmbeddedBranding()
        {
            try
            {
                Assembly assembly = Assembly.GetExecutingAssembly();
                using (Stream stream = assembly.GetManifestResourceStream("SkinCheck.icon.ico"))
                {
                    if (stream != null)
                        Icon = new Icon(stream);
                }
            }
            catch { }
        }

        private void BuildInterface()
        {
            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.ColumnCount = 1;
            root.RowCount = 5;
            root.Padding = new Padding(12);
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 74));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 84));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 72));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 76));
            Controls.Add(root);

            Panel header = new Panel();
            header.Dock = DockStyle.Fill;
            Label title = new Label();
            title.Text = "SkinCheck";
            title.Font = new Font("Segoe UI Semibold", 20F, FontStyle.Bold);
            title.ForeColor = Color.FromArgb(27, 46, 76);
            title.Location = new Point(2, 0);
            title.AutoSize = true;
            _subtitle.ForeColor = Color.FromArgb(80, 94, 112);
            _subtitle.Location = new Point(4, 40);
            _subtitle.AutoSize = true;
            _languageLabel.AutoSize = true;
            _languageLabel.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _languageLabel.Location = new Point(690, 8);
            _languageBox.DropDownStyle = ComboBoxStyle.DropDownList;
            _languageBox.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _languageBox.Items.AddRange(new object[] { "Español", "English", "Português (Brasil)" });
            _languageBox.SelectedIndex = 0;
            _languageBox.Width = 176;
            _languageBox.Location = new Point(770, 4);
            _languageBox.SelectedIndexChanged += LanguageChanged;
            header.Resize += delegate(object sender, EventArgs e) {
                _languageLabel.Left = Math.Max(400, header.ClientSize.Width - 286);
                _languageBox.Left = Math.Max(500, header.ClientSize.Width - 196);
            };
            header.Controls.Add(title);
            header.Controls.Add(_subtitle);
            header.Controls.Add(_languageLabel);
            header.Controls.Add(_languageBox);
            root.Controls.Add(header, 0, 0);

            _filterGroup.Text = "";
            _filterGroup.Dock = DockStyle.Fill;
            _filterGroup.Padding = new Padding(8, 4, 8, 4);
            FlowLayoutPanel filterFlow = new FlowLayoutPanel();
            filterFlow.Dock = DockStyle.Fill;
            filterFlow.AutoScroll = true;
            filterFlow.WrapContents = true;
            filterFlow.FlowDirection = FlowDirection.LeftToRight;
            CheckBox[] checks = new CheckBox[] {
                _executionFilter, _commandsFilter, _peFilter,
                _rwFilter, _urlFilter, _entropyFilter,
                _persistenceFilter, _credentialFilter, _signatureFilter, _injectionFilter
            };
            for (int i = 0; i < checks.Length; i++)
            {
                checks[i].Checked = true;
                checks[i].AutoSize = true;
                checks[i].Margin = new Padding(5, 8, 16, 3);
                filterFlow.Controls.Add(checks[i]);
            }
            _filterGroup.Controls.Add(filterFlow);
            root.Controls.Add(_filterGroup, 0, 1);

            FlowLayoutPanel actions = new FlowLayoutPanel();
            actions.Dock = DockStyle.Fill;
            actions.WrapContents = true;
            actions.AutoScroll = true;
            actions.FlowDirection = FlowDirection.LeftToRight;
            actions.Padding = new Padding(0, 3, 0, 0);
            _addButton.Click += AddFiles;
            _removeButton.Click += RemoveSelected;
            _clearButton.Click += ClearFiles;
            _analyzeButton.Click += AnalyzeFiles;
            _vtButton.Click += SearchVirusTotal;
            _saveButton.Click += SaveReport;
            StyleButton(_addButton, false);
            StyleButton(_removeButton, false);
            StyleButton(_clearButton, false);
            StyleButton(_analyzeButton, true);
            StyleButton(_vtButton, false);
            StyleButton(_saveButton, false);
            _vtButton.Enabled = false;
            actions.Controls.Add(_addButton);
            actions.Controls.Add(_removeButton);
            actions.Controls.Add(_clearButton);
            actions.Controls.Add(_analyzeButton);
            actions.Controls.Add(_vtButton);
            actions.Controls.Add(_saveButton);
            root.Controls.Add(actions, 0, 2);

            SplitContainer split = new SplitContainer();
            split.Dock = DockStyle.Fill;
            split.Orientation = Orientation.Horizontal;
            split.SplitterDistance = 190;
            split.Panel1MinSize = 95;
            split.Panel2MinSize = 110;
            split.BackColor = Color.FromArgb(246, 248, 251);
            _files.Dock = DockStyle.Fill;
            _files.View = View.Details;
            _files.FullRowSelect = true;
            _files.GridLines = true;
            _files.MultiSelect = false;
            _files.HideSelection = false;
            _files.AllowDrop = true;
            _files.Columns.Add("File", 205);
            _files.Columns.Add("Location", 540);
            _files.Columns.Add("Result", 205);
            _files.DragEnter += FileDragEnter;
            _files.DragDrop += FileDragDrop;
            _files.SelectedIndexChanged += SelectedFileChanged;
            split.Panel1.Controls.Add(_files);

            _report.Dock = DockStyle.Fill;
            _report.ReadOnly = true;
            _report.BorderStyle = BorderStyle.FixedSingle;
            _report.BackColor = Color.White;
            _report.Font = new Font("Consolas", 9F);
            split.Panel2.Controls.Add(_report);
            root.Controls.Add(split, 0, 3);

            TableLayoutPanel footer = new TableLayoutPanel();
            footer.Dock = DockStyle.Fill;
            footer.ColumnCount = 2;
            footer.RowCount = 3;
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 132));
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            footer.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            footer.RowStyles.Add(new RowStyle(SizeType.Absolute, 25));
            footer.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            PictureBox logo = new PictureBox();
            logo.Dock = DockStyle.Fill;
            logo.SizeMode = PictureBoxSizeMode.Zoom;
            logo.Margin = new Padding(0, 1, 8, 1);
            try
            {
                using (Stream stream = Assembly.GetExecutingAssembly()
                    .GetManifestResourceStream("SkinCheck.otherclap-logo.png"))
                {
                    if (stream != null)
                    {
                        using (Image image = Image.FromStream(stream))
                            logo.Image = new Bitmap(image);
                    }
                }
            }
            catch { }
            footer.Controls.Add(logo, 0, 0);
            _copyright.Dock = DockStyle.Fill;
            _copyright.TextAlign = ContentAlignment.MiddleLeft;
            _copyright.AutoEllipsis = true;
            _copyright.ForeColor = Color.FromArgb(62, 76, 96);
            footer.Controls.Add(_copyright, 1, 0);

            FlowLayoutPanel linkPanel = new FlowLayoutPanel();
            linkPanel.Dock = DockStyle.Fill;
            linkPanel.WrapContents = true;
            linkPanel.AutoScroll = true;
            linkPanel.FlowDirection = FlowDirection.LeftToRight;
            linkPanel.Margin = new Padding(0);
            for (int i = 0; i < _links.Length; i++)
            {
                LinkLabel link = new LinkLabel();
                link.AutoSize = true;
                link.Margin = new Padding(1, 2, 15, 0);
                link.Tag = _linkUrls[i];
                link.LinkClicked += OpenLink;
                _links[i] = link;
                linkPanel.Controls.Add(link);
            }
            footer.Controls.Add(linkPanel, 0, 1);
            footer.SetColumnSpan(linkPanel, 2);

            _status.Dock = DockStyle.Fill;
            _status.TextAlign = ContentAlignment.MiddleLeft;
            _status.ForeColor = Color.FromArgb(80, 94, 112);
            footer.Controls.Add(_status, 0, 2);
            footer.SetColumnSpan(_status, 2);
            root.Controls.Add(footer, 0, 4);
        }

        private static void StyleButton(Button button, bool primary)
        {
            button.AutoSize = true;
            button.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            button.MinimumSize = new Size(84, 35);
            button.Height = 35;
            button.Padding = new Padding(9, 3, 9, 3);
            button.Margin = new Padding(0, 0, 8, 4);
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderSize = 1;
            button.BackColor = primary ? Color.FromArgb(32, 104, 180) : Color.White;
            button.ForeColor = primary ? Color.White : Color.FromArgb(37, 55, 78);
            button.FlatAppearance.BorderColor = primary
                ? Color.FromArgb(32, 104, 180)
                : Color.FromArgb(204, 213, 224);
        }

        private void ApplyLanguage()
        {
            Text = LanguageCatalog.T(_language, "window_title");
            _subtitle.Text = LanguageCatalog.T(_language, "subtitle");
            _languageLabel.Text = LanguageCatalog.T(_language, "language");
            _filterGroup.Text = LanguageCatalog.T(_language, "filter_group");
            _executionFilter.Text = LanguageCatalog.T(_language, "filter_execution");
            _commandsFilter.Text = LanguageCatalog.T(_language, "filter_commands");
            _peFilter.Text = LanguageCatalog.T(_language, "filter_pe");
            _rwFilter.Text = LanguageCatalog.T(_language, "filter_rw");
            _urlFilter.Text = LanguageCatalog.T(_language, "filter_urls");
            _entropyFilter.Text = LanguageCatalog.T(_language, "filter_entropy");
            _persistenceFilter.Text = LanguageCatalog.T(_language, "filter_persistence");
            _credentialFilter.Text = LanguageCatalog.T(_language, "filter_credentials");
            _signatureFilter.Text = LanguageCatalog.T(_language, "filter_signature");
            _injectionFilter.Text = LanguageCatalog.T(_language, "filter_injection");
            _addButton.Text = LanguageCatalog.T(_language, "add");
            _removeButton.Text = LanguageCatalog.T(_language, "remove");
            _clearButton.Text = LanguageCatalog.T(_language, "clear");
            _analyzeButton.Text = LanguageCatalog.T(_language, "analyze");
            _vtButton.Text = LanguageCatalog.T(_language, "vt");
            _saveButton.Text = LanguageCatalog.T(_language, "save");
            _files.Columns[0].Text = LanguageCatalog.T(_language, "column_file");
            _files.Columns[1].Text = LanguageCatalog.T(_language, "column_path");
            _files.Columns[2].Text = LanguageCatalog.T(_language, "column_result");
            _copyright.Text = LanguageCatalog.T(_language, "footer_copyright") + " " +
                LanguageCatalog.T(_language, "footer_restriction");
            string[] linkKeys = new string[] {
                "link_site", "link_github", "link_viewer", "link_discord", "link_samp"
            };
            for (int i = 0; i < _links.Length; i++)
                _links[i].Text = LanguageCatalog.T(_language, linkKeys[i]);

            if (_results.Count == 0)
                _report.Text = LanguageCatalog.T(_language, "intro");
            else if (_files.SelectedItems.Count > 0)
            {
                string path = _files.SelectedItems[0].Tag as string;
                if (path != null && _results.ContainsKey(path))
                    ShowReport(_results[path]);
                else
                    ShowAllReports();
            }
            else
                ShowAllReports();

            for (int i = 0; i < _files.Items.Count; i++)
            {
                ListViewItem row = _files.Items[i];
                string path = row.Tag as string;
                if (path != null && _results.ContainsKey(path))
                    row.SubItems[2].Text = StaticAnalyzer.Summary(_results[path], _language);
                else
                    row.SubItems[2].Text = LanguageCatalog.T(_language, "pending");
            }
            _status.Text = LanguageCatalog.T(_language, "status_ready");
        }

        private void LanguageChanged(object sender, EventArgs e)
        {
            if (_languageBox.SelectedIndex == 1)
                _language = "en";
            else if (_languageBox.SelectedIndex == 2)
                _language = "pt-BR";
            else
                _language = "es";
            ApplyLanguage();
        }

        private void AddFiles(object sender, EventArgs e)
        {
            using (OpenFileDialog dialog = new OpenFileDialog())
            {
                dialog.Title = LanguageCatalog.T(_language, "dialog_open_title");
                dialog.Filter = LanguageCatalog.T(_language, "dialog_all_files");
                dialog.Multiselect = true;
                if (dialog.ShowDialog(this) == DialogResult.OK)
                    AddPaths(dialog.FileNames);
            }
        }

        private void FileDragEnter(object sender, DragEventArgs e)
        {
            e.Effect = e.Data.GetDataPresent(DataFormats.FileDrop)
                ? DragDropEffects.Copy : DragDropEffects.None;
        }

        private void FileDragDrop(object sender, DragEventArgs e)
        {
            string[] paths = e.Data.GetData(DataFormats.FileDrop) as string[];
            if (paths != null)
                AddPaths(paths);
        }

        private void AddPaths(string[] paths)
        {
            int added = 0;
            for (int i = 0; i < paths.Length; i++)
            {
                if (!File.Exists(paths[i]) || HasPath(paths[i]))
                    continue;
                ListViewItem row = new ListViewItem(Path.GetFileName(paths[i]));
                row.SubItems.Add(paths[i]);
                row.SubItems.Add(LanguageCatalog.T(_language, "pending"));
                row.Tag = paths[i];
                _files.Items.Add(row);
                added++;
            }
            _status.Text = added == 0
                ? LanguageCatalog.T(_language, "status_no_added")
                : LanguageCatalog.T(_language, "status_added", added);
        }

        private bool HasPath(string path)
        {
            for (int i = 0; i < _files.Items.Count; i++)
            {
                string existing = _files.Items[i].Tag as string;
                if (String.Equals(existing, path, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private void RemoveSelected(object sender, EventArgs e)
        {
            if (_files.SelectedItems.Count == 0)
                return;
            string path = _files.SelectedItems[0].Tag as string;
            _files.Items.Remove(_files.SelectedItems[0]);
            if (path != null && _results.ContainsKey(path))
                _results.Remove(path);
            _status.Text = LanguageCatalog.T(_language, "status_removed");
            _vtButton.Enabled = false;
            if (_results.Count == 0)
                _report.Text = LanguageCatalog.T(_language, "intro");
            else
                ShowAllReports();
        }

        private void ClearFiles(object sender, EventArgs e)
        {
            _files.Items.Clear();
            _results.Clear();
            _report.Text = LanguageCatalog.T(_language, "intro");
            _vtButton.Enabled = false;
            _status.Text = LanguageCatalog.T(_language, "status_empty");
        }

        private void AnalyzeFiles(object sender, EventArgs e)
        {
            if (_files.Items.Count == 0)
            {
                MessageBox.Show(this, LanguageCatalog.T(_language, "message_add_first"),
                    LanguageCatalog.T(_language, "info_title"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            ScanOptions options = new ScanOptions();
            options.ExecutionMarkers = _executionFilter.Checked;
            options.Commands = _commandsFilter.Checked;
            options.ExecutableSignatures = _peFilter.Checked;
            options.RenderWareStructure = _rwFilter.Checked;
            options.EmbeddedUrls = _urlFilter.Checked;
            options.Entropy = _entropyFilter.Checked;
            options.NetworkIndicators = _urlFilter.Checked;
            options.PersistenceIndicators = _persistenceFilter.Checked;
            options.CredentialIndicators = _credentialFilter.Checked;
            options.Authenticode = _signatureFilter.Checked;
            options.MemoryInjection = _injectionFilter.Checked;
            _results.Clear();
            _report.Clear();
            _analyzeButton.Enabled = false;
            _status.Text = LanguageCatalog.T(_language, "status_analyzing");
            Application.DoEvents();
            for (int i = 0; i < _files.Items.Count; i++)
            {
                ListViewItem row = _files.Items[i];
                string path = row.Tag as string;
                FileResult result = StaticAnalyzer.Analyze(path, options);
                _results[path] = result;
                row.SubItems[2].Text = StaticAnalyzer.Summary(result, _language);
                row.BackColor = result.Score >= 50
                    ? Color.FromArgb(255, 231, 229)
                    : (result.Score >= 20 ? Color.FromArgb(255, 246, 220) : Color.White);
                row.ForeColor = Color.FromArgb(37, 55, 78);
                _status.Text = LanguageCatalog.T(_language, "status_progress", i + 1, _files.Items.Count);
                Application.DoEvents();
            }
            _analyzeButton.Enabled = true;
            _vtButton.Enabled = true;
            _status.Text = LanguageCatalog.T(_language, "status_done");
            if (_files.SelectedItems.Count > 0)
            {
                string selected = _files.SelectedItems[0].Tag as string;
                if (selected != null && _results.ContainsKey(selected))
                    ShowReport(_results[selected]);
            }
            else
                ShowAllReports();
        }

        private void SelectedFileChanged(object sender, EventArgs e)
        {
            if (_files.SelectedItems.Count == 0)
                return;
            string path = _files.SelectedItems[0].Tag as string;
            if (path != null && _results.ContainsKey(path))
                ShowReport(_results[path]);
        }

        private void ShowAllReports()
        {
            StringBuilder text = new StringBuilder();
            foreach (ListViewItem row in _files.Items)
            {
                string path = row.Tag as string;
                if (path != null && _results.ContainsKey(path))
                    text.AppendLine(StaticAnalyzer.FormatReport(_results[path], _language));
            }
            _report.Text = text.ToString();
        }

        private void ShowReport(FileResult result)
        {
            _report.Text = StaticAnalyzer.FormatReport(result, _language);
        }

        private void SearchVirusTotal(object sender, EventArgs e)
        {
            if (_files.SelectedItems.Count == 0)
            {
                MessageBox.Show(this, LanguageCatalog.T(_language, "message_select_vt"),
                    LanguageCatalog.T(_language, "info_title"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string path = _files.SelectedItems[0].Tag as string;
            if (path == null || !_results.ContainsKey(path) || String.IsNullOrEmpty(_results[path].Hash))
            {
                MessageBox.Show(this, LanguageCatalog.T(_language, "message_analyze_first"),
                    LanguageCatalog.T(_language, "info_title"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string url = "https://www.virustotal.com/gui/file/" + _results[path].Hash;
            try
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
                _status.Text = LanguageCatalog.T(_language, "status_hash_opened");
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, LanguageCatalog.T(_language, "message_open_error", ex.Message),
                    LanguageCatalog.T(_language, "error_title"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void SaveReport(object sender, EventArgs e)
        {
            if (String.IsNullOrWhiteSpace(_report.Text))
            {
                MessageBox.Show(this, LanguageCatalog.T(_language, "message_analyze_first"),
                    LanguageCatalog.T(_language, "info_title"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            using (SaveFileDialog dialog = new SaveFileDialog())
            {
                dialog.Title = LanguageCatalog.T(_language, "dialog_save_title");
                dialog.Filter = LanguageCatalog.T(_language, "dialog_save_filter");
                dialog.FileName = LanguageCatalog.T(_language, "dialog_save_name");
                if (dialog.ShowDialog(this) == DialogResult.OK)
                {
                    File.WriteAllText(dialog.FileName, _report.Text, Encoding.UTF8);
                    _status.Text = LanguageCatalog.T(_language, "status_report_saved", dialog.FileName);
                }
            }
        }

        private void OpenLink(object sender, LinkLabelLinkClickedEventArgs e)
        {
            LinkLabel link = sender as LinkLabel;
            if (link == null || link.Tag == null)
                return;
            try
            {
                Process.Start(new ProcessStartInfo(link.Tag.ToString()) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, LanguageCatalog.T(_language, "message_open_error", ex.Message),
                    LanguageCatalog.T(_language, "error_title"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    internal static class StaticAnalyzer
    {
        private static readonly string[] ExecutionMarkers = new string[] {
            "shellexecutea", "shellexecutew", "winexec", "createprocessa",
            "createprocessw", "virtualalloc", "virtualprotect",
            "writeprocessmemory", "createremotethread", "urldownloadtofile",
            "shell32.dll", "loadlibrarya", "loadlibraryw"
        };
        private static readonly string[] CommandMarkers = new string[] {
            "powershell", "cmd.exe", "rundll32", "regsvr32", "mshta",
            "wscript.shell", "cscript.exe", "certutil", "bitsadmin"
        };
        private static readonly string[] RceMarkers = new string[] {
            "shellexecutea", "shellexecutew", "winexec", "createprocessa",
            "createprocessw", "system(", "popen(", "execve", "runtime.exec",
            "processbuilder", "invoke-expression", "-encodedcommand",
            "cmd /c", "powershell -enc", "/bin/sh", "/bin/bash", "bash -c", "eval("
        };
        private static readonly string[] InjectionMarkers = new string[] {
            "virtualalloc", "virtualprotect", "writeprocessmemory",
            "createremotethread", "ntwritevirtualmemory", "ntcreatethreadex",
            "queueuserapc", "mapviewoffile", "mprotect", "ptrace"
        };
        private static readonly string[] NetworkMarkers = new string[] {
            "wsastartup", "getaddrinfo", "socket(", "connect(", "internetopen",
            "winhttpopen", "urldownloadtofile", "curl_easy_perform",
            "httpclient", "webclient"
        };
        private static readonly string[] PersistenceMarkers = new string[] {
            "currentversion\\run", "currentversion\\runonce", "createservice",
            "startservice", "schtasks", "\\startup\\", "/etc/cron",
            "crontab", "launchagents", "systemd/"
        };
        private static readonly string[] CredentialMarkers = new string[] {
            "credread", "cryptunprotectdata", "lsass", "sam\\",
            "getasynckeystate", "keylog", "credentialmanager"
        };
        private static readonly string[] ObfuscationMarkers = new string[] {
            "frombase64string", "base64.b64decode", "-encodedcommand",
            "upx0", "upx1", "aspack", "mpress", "confuserex"
        };
        private static readonly Regex IPv4Pattern = new Regex(
            @"(?<![0-9.])(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?![0-9.])",
            RegexOptions.Compiled);
        private static readonly Regex IPv6Pattern = new Regex(
            @"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])",
            RegexOptions.Compiled);
        private static readonly Regex DomainPattern = new Regex(
            @"(?i)(?<![a-z0-9_-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![a-z0-9-])",
            RegexOptions.Compiled);

        public static FileResult Analyze(string path, ScanOptions options)
        {
            FileResult result = new FileResult();
            result.Path = path;
            result.NetworkScanPerformed = options.NetworkIndicators;
            try
            {
                FileInfo info = new FileInfo(path);
                result.Length = info.Length;
                using (FileStream stream = File.OpenRead(path))
                using (SHA256 sha = SHA256.Create())
                    result.Hash = ToHex(sha.ComputeHash(stream));

                if (result.Length > 100L * 1024L * 1024L)
                {
                    result.ErrorKey = "large_file";
                    return result;
                }
                byte[] data = File.ReadAllBytes(path);
                string extension = Path.GetExtension(path).ToLowerInvariant();
                bool executableExtension = IsExecutableExtension(extension);
                result.IsRenderWareAsset = extension == ".dff" || extension == ".txd";
                result.IsPe = IsValidPe(data, 0);
                bool isElf = IsElf(data, 0);
                int embeddedPe = -1;
                int embeddedElf = -1;
                if (options.ExecutableSignatures && !result.IsPe)
                {
                    embeddedPe = FindEmbeddedPe(data);
                    if (!isElf)
                        embeddedElf = FindEmbeddedElf(data);
                }

                if (options.ExecutableSignatures)
                {
                    if (result.IsPe && !executableExtension)
                    {
                        result.Score += 75;
                        Add(result, "finding_pe_mismatch", String.IsNullOrEmpty(extension) ? "(none)" : extension);
                    }
                    else if (isElf && !executableExtension)
                    {
                        result.Score += 65;
                        Add(result, "finding_elf_mismatch", String.IsNullOrEmpty(extension) ? "(none)" : extension);
                    }
                    else if (embeddedPe >= 0)
                    {
                        result.Score += 75;
                        Add(result, "finding_embedded_pe", embeddedPe);
                    }
                    if (executableExtension && !result.IsPe && !isElf)
                    {
                        result.Score += 25;
                        Add(result, "finding_exe_invalid");
                    }
                    if (embeddedElf >= 0)
                    {
                        result.Score += 65;
                        Add(result, "finding_embedded_elf", embeddedElf);
                    }
                }
                if (options.RenderWareStructure && result.IsRenderWareAsset)
                    CheckRenderWareHeader(data, extension, result);

                bool hasExecutionMarker = false;
                List<string> foundExecution = new List<string>();
                if (options.ExecutionMarkers)
                {
                    for (int i = 0; i < ExecutionMarkers.Length; i++)
                    {
                        if (ContainsText(data, ExecutionMarkers[i]))
                        {
                            foundExecution.Add(ExecutionMarkers[i]);
                            hasExecutionMarker = true;
                        }
                    }
                    if (foundExecution.Count > 0)
                    {
                        Add(result, "finding_execution", String.Join(", ", foundExecution.ToArray()));
                        if (result.IsRenderWareAsset)
                            result.Score += 20;
                        else if (!result.IsPe)
                            result.Score += 12;
                        else
                            result.Score += Math.Min(20, foundExecution.Count * 3);
                    }
                }

                bool hasCommandMarker = false;
                List<string> foundCommands = new List<string>();
                if (options.Commands)
                {
                    for (int i = 0; i < CommandMarkers.Length; i++)
                    {
                        if (ContainsText(data, CommandMarkers[i]))
                        {
                            foundCommands.Add(CommandMarkers[i]);
                            hasCommandMarker = true;
                        }
                    }
                    if (foundCommands.Count > 0)
                    {
                        Add(result, "finding_commands", String.Join(", ", foundCommands.ToArray()));
                        if (result.IsRenderWareAsset)
                            result.Score += 25;
                        else if (!result.IsPe)
                            result.Score += 10;
                        else
                            result.Score += Math.Min(15, foundCommands.Count * 2);
                    }
                }

                List<string> foundRce = FindMarkers(data, RceMarkers);
                bool hasRceMarker = foundRce.Count > 0;
                if (foundRce.Count > 0)
                {
                    Add(result, "finding_rce", String.Join(", ", foundRce.ToArray()));
                    if (result.IsRenderWareAsset)
                        result.Score += 20;
                    else if (!result.IsPe)
                        result.Score += Math.Min(15, foundRce.Count * 3);
                    else
                        result.Score += Math.Min(8, foundRce.Count);
                }

                bool hasInjectionMarker = false;
                if (options.MemoryInjection)
                {
                    List<string> injection = FindMarkers(data, InjectionMarkers);
                    if (injection.Count > 0)
                    {
                        hasInjectionMarker = true;
                        Add(result, "finding_injection", String.Join(", ", injection.ToArray()));
                        if (result.IsRenderWareAsset)
                            result.Score += 10;
                        else if (!result.IsPe)
                            result.Score += Math.Min(12, injection.Count * 3);
                        else
                            result.Score += Math.Min(8, injection.Count * 2);
                    }
                }

                bool hasNetworkIndicator = false;
                if (options.NetworkIndicators)
                {
                    List<string> networkApis = FindMarkers(data, NetworkMarkers);
                    result.Addresses = ExtractAddresses(data);
                    if (networkApis.Count > 0)
                    {
                        hasNetworkIndicator = true;
                        Add(result, "finding_network_apis", String.Join(", ", networkApis.ToArray()));
                    }
                    if (result.Addresses.Count > 0)
                    {
                        hasNetworkIndicator = true;
                        Add(result, "finding_addresses", String.Join(", ", result.Addresses.ToArray()));
                    }
                }

                if (options.EmbeddedUrls)
                {
                    result.Urls = ExtractUrls(data);
                    if (result.Urls.Count > 0)
                    {
                        hasNetworkIndicator = true;
                        Add(result, "finding_urls");
                    }
                }
                if (result.IsRenderWareAsset && (hasExecutionMarker || hasRceMarker) && hasNetworkIndicator)
                    result.Score += 20;
                if (result.IsRenderWareAsset && hasInjectionMarker &&
                    (hasRceMarker || hasNetworkIndicator))
                    result.Score += 15;
                if (result.IsRenderWareAsset && hasExecutionMarker && hasCommandMarker)
                    result.Score += 15;

                if (options.PersistenceIndicators)
                {
                    List<string> persistence = FindMarkers(data, PersistenceMarkers);
                    if (persistence.Count > 0)
                    {
                        Add(result, "finding_persistence", String.Join(", ", persistence.ToArray()));
                        result.Score += Math.Min(10, persistence.Count * 2);
                    }
                }

                if (options.CredentialIndicators)
                {
                    List<string> credentials = FindMarkers(data, CredentialMarkers);
                    if (credentials.Count > 0)
                        Add(result, "finding_credentials", String.Join(", ", credentials.ToArray()));
                }

                if (options.Entropy)
                {
                    List<string> obfuscation = FindMarkers(data, ObfuscationMarkers);
                    if (obfuscation.Count > 0)
                    {
                        Add(result, "finding_script_encoding", String.Join(", ", obfuscation.ToArray()));
                        if (!result.IsPe && !result.IsRenderWareAsset)
                            result.Score += 5;
                    }
                }

                if (options.Authenticode && result.IsPe)
                {
                    try
                    {
                        using (X509Certificate certificate = X509Certificate.CreateFromSignedFile(path))
                            Add(result, "finding_signed");
                    }
                    catch (CryptographicException)
                    {
                        Add(result, "finding_unsigned");
                    }
                    catch (Exception ex)
                    {
                        Add(result, "finding_signature_error", ex.Message);
                    }
                }

                if (options.Entropy && !result.IsRenderWareAsset)
                {
                    result.Entropy = CalculateEntropy(data);
                    result.HasEntropy = true;
                    if (result.Entropy >= 7.35 && result.Length >= 4096)
                    {
                        Add(result, "finding_entropy");
                        result.Score += 8;
                    }
                }
                if (result.Signals.Count == 0)
                    Add(result, "finding_none");
                result.Score = Math.Min(100, result.Score);
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }
            return result;
        }

        private static void Add(FileResult result, string key, params object[] arguments)
        {
            result.Signals.Add(new Finding(key, arguments));
        }

        private static List<string> FindMarkers(byte[] data, string[] markers)
        {
            List<string> found = new List<string>();
            for (int i = 0; i < markers.Length; i++)
                if (ContainsText(data, markers[i]))
                    found.Add(markers[i]);
            return found;
        }

        private static List<string> ExtractAddresses(byte[] data)
        {
            List<string> addresses = new List<string>();
            HashSet<string> unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            ScanPrintableRuns(data, false, delegate(string value) {
                CollectAddresses(value, addresses, unique);
            });
            ScanPrintableRuns(data, true, delegate(string value) {
                CollectAddresses(value, addresses, unique);
            });
            return addresses;
        }

        private static void CollectAddresses(string value, List<string> addresses, HashSet<string> unique)
        {
            MatchCollection ipv4Matches = IPv4Pattern.Matches(value);
            for (int i = 0; i < ipv4Matches.Count && addresses.Count < 30; i++)
            {
                string candidate = ipv4Matches[i].Value;
                IPAddress parsed;
                if (IPAddress.TryParse(candidate, out parsed) &&
                    parsed.GetAddressBytes().Length == 4 &&
                    unique.Add("IP: " + candidate))
                    addresses.Add("IP: " + candidate);
            }

            MatchCollection ipv6Matches = IPv6Pattern.Matches(value);
            for (int i = 0; i < ipv6Matches.Count && addresses.Count < 30; i++)
            {
                string candidate = ipv6Matches[i].Value;
                IPAddress parsed;
                if (IPAddress.TryParse(candidate, out parsed) &&
                    parsed.GetAddressBytes().Length == 16 &&
                    unique.Add("IPv6: " + parsed.ToString()))
                    addresses.Add("IPv6: " + parsed.ToString());
            }

            MatchCollection domainMatches = DomainPattern.Matches(value);
            for (int i = 0; i < domainMatches.Count && addresses.Count < 30; i++)
            {
                string candidate = domainMatches[i].Value.TrimEnd('.');
                string suffix = candidate.Substring(candidate.LastIndexOf('.') + 1).ToLowerInvariant();
                if (IsCommonFileExtension(suffix))
                    continue;
                if (unique.Add("Host: " + candidate))
                    addresses.Add("Host: " + candidate);
            }
        }

        private static bool IsCommonFileExtension(string extension)
        {
            string[] extensions = new string[] {
                "exe", "dll", "dff", "txd", "sys", "ocx", "scr", "dat", "txt",
                "bin", "cfg", "ini", "log", "zip", "rar", "png", "jpg", "jpeg",
                "json", "xml", "pdf", "ps1", "bat", "cmd", "css", "js", "mp3", "mp4"
            };
            for (int i = 0; i < extensions.Length; i++)
                if (extension == extensions[i])
                    return true;
            return false;
        }

        private static void ScanPrintableRuns(byte[] data, bool unicode, Action<string> callback)
        {
            StringBuilder run = new StringBuilder();
            int step = unicode ? 2 : 1;
            for (int i = 0; i + (unicode ? 1 : 0) < data.Length; i += step)
            {
                int value = data[i];
                bool printable = value >= 32 && value <= 126 &&
                    (!unicode || data[i + 1] == 0);
                if (printable)
                {
                    if (run.Length < 4096)
                        run.Append((char)value);
                }
                else
                {
                    if (run.Length >= 4)
                        callback(run.ToString());
                    run.Length = 0;
                }
            }
            if (run.Length >= 4)
                callback(run.ToString());
        }

        private static bool IsElf(byte[] data, int offset)
        {
            return offset >= 0 && offset + 4 <= data.Length &&
                data[offset] == 0x7F && data[offset + 1] == (byte)'E' &&
                data[offset + 2] == (byte)'L' && data[offset + 3] == (byte)'F';
        }

        private static int FindEmbeddedElf(byte[] data)
        {
            for (int i = 1; i + 4 <= data.Length; i++)
                if (IsElf(data, i))
                    return i;
            return -1;
        }

        private static void CheckRenderWareHeader(byte[] data, string extension, FileResult result)
        {
            if (data.Length < 12)
            {
                result.Score += 15;
                Add(result, "finding_rw_short");
                return;
            }
            uint expectedType = extension == ".dff" ? 0x10U : 0x16U;
            uint actualType = ReadUInt32(data, 0);
            uint declaredSize = ReadUInt32(data, 4);
            if (actualType != expectedType)
            {
                result.Score += 20;
                Add(result, "finding_rw_id", extension);
                return;
            }
            if ((long)declaredSize + 12L != data.Length)
            {
                result.Score += 15;
                Add(result, "finding_rw_size");
            }
            else
                Add(result, "finding_rw_valid", extension);
        }

        private static bool IsExecutableExtension(string extension)
        {
            return extension == ".exe" || extension == ".dll" || extension == ".sys" ||
                extension == ".ocx" || extension == ".scr" || extension == ".com" ||
                extension == ".elf" || extension == ".so";
        }

        private static bool IsValidPe(byte[] data, int offset)
        {
            if (offset < 0 || offset + 64 > data.Length)
                return false;
            if (data[offset] != (byte)'M' || data[offset + 1] != (byte)'Z')
                return false;
            int relative = ReadInt32(data, offset + 0x3C);
            if (relative < 0 || relative > 16 * 1024 * 1024)
                return false;
            long signature = (long)offset + relative;
            return signature + 4 <= data.Length &&
                data[(int)signature] == (byte)'P' &&
                data[(int)signature + 1] == (byte)'E' &&
                data[(int)signature + 2] == 0 &&
                data[(int)signature + 3] == 0;
        }

        private static int FindEmbeddedPe(byte[] data)
        {
            for (int i = 1; i + 64 < data.Length; i++)
                if (data[i] == (byte)'M' && data[i + 1] == (byte)'Z' && IsValidPe(data, i))
                    return i;
            return -1;
        }

        private static uint ReadUInt32(byte[] data, int offset)
        {
            return (uint)(data[offset] | (data[offset + 1] << 8) |
                (data[offset + 2] << 16) | (data[offset + 3] << 24));
        }

        private static int ReadInt32(byte[] data, int offset)
        {
            return unchecked((int)ReadUInt32(data, offset));
        }

        private static bool ContainsText(byte[] data, string text)
        {
            if (FindPattern(data, Encoding.ASCII.GetBytes(text), 0) >= 0)
                return true;
            return FindPattern(data, Encoding.Unicode.GetBytes(text), 0) >= 0;
        }

        private static int FindPattern(byte[] data, byte[] pattern, int start)
        {
            if (pattern.Length == 0 || data.Length < pattern.Length)
                return -1;
            byte firstLower = ToLowerAscii(pattern[0]);
            byte firstUpper = ToUpperAscii(firstLower);
            int position = Math.Max(0, start);
            while (position <= data.Length - pattern.Length)
            {
                int lower = Array.IndexOf(data, firstLower, position);
                int upper = firstUpper == firstLower ? -1 : Array.IndexOf(data, firstUpper, position);
                int candidate;
                if (lower < 0)
                    candidate = upper;
                else if (upper < 0)
                    candidate = lower;
                else
                    candidate = Math.Min(lower, upper);
                if (candidate < 0 || candidate > data.Length - pattern.Length)
                    return -1;
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (ToLowerAscii(data[candidate + j]) != ToLowerAscii(pattern[j]))
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                    return candidate;
                position = candidate + 1;
            }
            return -1;
        }

        private static byte ToLowerAscii(byte value)
        {
            return value >= (byte)'A' && value <= (byte)'Z' ? (byte)(value + 32) : value;
        }

        private static byte ToUpperAscii(byte value)
        {
            return value >= (byte)'a' && value <= (byte)'z' ? (byte)(value - 32) : value;
        }

        private static List<string> ExtractUrls(byte[] data)
        {
            List<string> urls = new List<string>();
            CollectUrls(data, "http://", false, urls);
            CollectUrls(data, "https://", false, urls);
            CollectUrls(data, "http://", true, urls);
            CollectUrls(data, "https://", true, urls);
            return urls;
        }

        private static void CollectUrls(byte[] data, string prefix, bool unicode, List<string> urls)
        {
            byte[] pattern = unicode ? Encoding.Unicode.GetBytes(prefix) : Encoding.ASCII.GetBytes(prefix);
            int start = 0;
            while (urls.Count < 10)
            {
                int index = FindPattern(data, pattern, start);
                if (index < 0)
                    return;
                StringBuilder value = new StringBuilder();
                int step = unicode ? 2 : 1;
                for (int i = index; i + (unicode ? 1 : 0) < data.Length && value.Length < 200; i += step)
                {
                    int ch = data[i];
                    if (unicode && data[i + 1] != 0)
                        break;
                    if (ch < 33 || ch > 126 || ch == '"' || ch == '\'' || ch == '<' || ch == '>')
                        break;
                    value.Append((char)ch);
                }
                string url = value.ToString().TrimEnd('.', ',', ';', ')', ']');
                if (url.Length > prefix.Length && !urls.Contains(url))
                    urls.Add(url);
                start = index + pattern.Length;
            }
        }

        private static double CalculateEntropy(byte[] data)
        {
            if (data.Length == 0)
                return 0;
            long[] counts = new long[256];
            for (int i = 0; i < data.Length; i++)
                counts[data[i]]++;
            double entropy = 0;
            for (int i = 0; i < counts.Length; i++)
            {
                if (counts[i] == 0)
                    continue;
                double probability = (double)counts[i] / data.Length;
                entropy -= probability * (Math.Log(probability) / Math.Log(2));
            }
            return entropy;
        }

        private static string ToHex(byte[] bytes)
        {
            StringBuilder text = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
                text.Append(bytes[i].ToString("X2"));
            return text.ToString();
        }

        public static string Summary(FileResult result, string language)
        {
            if (result.Error != null || result.ErrorKey != null)
                return LanguageCatalog.T(language, "summary_not_analyzed");
            if (result.Score >= 50)
                return LanguageCatalog.T(language, "summary_high", result.Score);
            if (result.Score >= 20)
                return LanguageCatalog.T(language, "summary_review", result.Score);
            return LanguageCatalog.T(language, "summary_clear", result.Score);
        }

        public static string FormatReport(FileResult result, string language)
        {
            StringBuilder report = new StringBuilder();
            report.AppendLine("============================================================");
            report.AppendLine(LanguageCatalog.T(language, "report_title"));
            report.AppendLine(LanguageCatalog.T(language, "report_file", result.Path));
            report.AppendLine(LanguageCatalog.T(language, "report_size", FormatSize(result.Length, language)));
            report.AppendLine(LanguageCatalog.T(language, "report_hash", result.Hash ?? "(unavailable)"));
            if (result.ErrorKey != null)
            {
                report.AppendLine(LanguageCatalog.T(language, "report_error",
                    LanguageCatalog.T(language, result.ErrorKey)));
                report.AppendLine(LanguageCatalog.T(language, "report_no_verdict"));
                return report.ToString();
            }
            if (result.Error != null)
            {
                report.AppendLine(LanguageCatalog.T(language, "report_error", result.Error));
                report.AppendLine(LanguageCatalog.T(language, "report_no_verdict"));
                return report.ToString();
            }

            report.AppendLine(LanguageCatalog.T(language, "report_verdict",
                Summary(result, language), result.Score));
            if (result.HasEntropy)
                report.AppendLine(LanguageCatalog.T(language, "report_entropy",
                    result.Entropy.ToString("0.00", LanguageCatalog.Culture(language))));
            report.AppendLine(LanguageCatalog.T(language, "report_indicators"));
            for (int i = 0; i < result.Signals.Count; i++)
            {
                Finding finding = result.Signals[i];
                report.AppendLine("  - " + LanguageCatalog.T(language, finding.Key, finding.Arguments));
            }
            if (result.Urls.Count > 0)
            {
                report.AppendLine(LanguageCatalog.T(language, "report_urls"));
                for (int i = 0; i < result.Urls.Count; i++)
                    report.AppendLine("  - " + result.Urls[i]);
            }
            if (result.NetworkScanPerformed)
            {
                if (result.Addresses.Count > 0)
                {
                    report.AppendLine(LanguageCatalog.T(language, "report_addresses"));
                    for (int i = 0; i < result.Addresses.Count; i++)
                        report.AppendLine("  - " + result.Addresses[i]);
                }
                else
                    report.AppendLine(LanguageCatalog.T(language, "report_no_addresses"));
            }
            report.AppendLine();
            report.AppendLine(LanguageCatalog.T(language, "report_limit"));
            report.AppendLine(LanguageCatalog.T(language, "report_no_clear"));
            report.AppendLine(LanguageCatalog.T(language, "report_rce_limit"));
            report.AppendLine(LanguageCatalog.T(language, "report_do_not_open"));
            report.AppendLine(LanguageCatalog.T(language, "footer_copyright") + " " +
                LanguageCatalog.T(language, "footer_restriction"));
            return report.ToString();
        }

        private static string FormatSize(long size, string language)
        {
            CultureInfo culture = LanguageCatalog.Culture(language);
            if (size >= 1024L * 1024L)
                return (size / (1024.0 * 1024.0)).ToString("0.00", culture) + " MB";
            if (size >= 1024L)
                return (size / 1024.0).ToString("0.0", culture) + " KB";
            return LanguageCatalog.T(language, "bytes", size);
        }
    }
}
