namespace ACT.Backup;

public class DatabaseBackup
{
    public static string BackupDatabase(string sourceDbPath, string backupDir)
    {
        Directory.CreateDirectory(backupDir);
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        var backupPath = Path.Combine(backupDir, $"artemis-backup-{timestamp}.db");

        File.Copy(sourceDbPath, backupPath, overwrite: true);
        return backupPath;
    }

    public static void RestoreDatabase(string backupDbPath, string targetDbPath)
    {
        File.Copy(backupDbPath, targetDbPath, overwrite: true);
    }

    public static List<string> ListBackups(string backupDir)
    {
        if (!Directory.Exists(backupDir))
        {
            return new List<string>();
        }

        return Directory.GetFiles(backupDir, "artemis-backup-*.db")
            .OrderByDescending(f => f)
            .ToList();
    }
}
