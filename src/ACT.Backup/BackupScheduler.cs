namespace ACT.Backup;

public class BackupScheduler
{
    private readonly Timer _timer;
    private readonly string _dbPath;
    private readonly string _backupDir;
    private readonly TimeSpan _interval;

    public BackupScheduler(string dbPath, string backupDir, TimeSpan interval)
    {
        _dbPath = dbPath;
        _backupDir = backupDir;
        _interval = interval;
        _timer = new Timer(_ => PerformBackup(), null, interval, interval);
    }

    private void PerformBackup()
    {
        try
        {
            DatabaseBackup.BackupDatabase(_dbPath, _backupDir);
        }
        catch (Exception)
        {
            // Log error
        }
    }

    public void Dispose()
    {
        _timer.Dispose();
    }
}
