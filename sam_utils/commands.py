import os
import sys
import subprocess
from pathlib import Path
from getpass import getpass

import click
import frappe
from frappe.commands import pass_context
from frappe.utils.backups import decrypt_backup, get_or_generate_backup_encryption_key
from frappe.installer import extract_files


@click.command("rest")
@click.argument("sql-file-path")
@click.option("--db-root-username", help='Root username for MariaDB/PostgreSQL, default "root"')
@click.option("--db-root-password", help="Root password for MariaDB/PostgreSQL")
@click.option("--db-name", help="Database name for the site")
@click.option("--admin-password", help="Administrator password for new site")
@click.option("--install-app", multiple=True, help="Install app after installation")
@click.option("--with-public-files", help="Restore public files, provide tar path")
@click.option("--with-private-files", help="Restore private files, provide tar path")
@click.option("--force", is_flag=True, default=False, help="Ignore validations/downgrade warnings")
@click.option("--encryption-key", help="Backup encryption key")
@pass_context
def rest(
    context,
    sql_file_path,
    db_root_username=None,
    db_root_password=None,
    db_name=None,
    admin_password=None,
    install_app=None,
    with_public_files=None,
    with_private_files=None,
    force=False,
    encryption_key=None,
):
    """
    Restore site database from an SQL file with real-time progress bar
    """

    if not context.sites:
        click.secho("❌ No site specified in this bench.", fg="red")
        return

    site = context.sites[0]
    frappe.init(site=site)

    # Handle encrypted backups
    sql_file_path = handle_encrypted_backup(sql_file_path, encryption_key)

    # Restore DB with progress
    restore_database_with_progress(
        sql_file_path,
        site,
        db_root_username or "root",
        db_root_password or "",
        db_name or frappe.conf.db_name,
    )

    # Set admin password
    set_admin_password(site, admin_password)

    # Install apps if requested
    if install_app:
        for app in install_app:
            frappe.get_installed_apps(consider_apps=[app])  # optional: install logic

    # Restore public/private files
    if with_public_files:
        restore_files(site, with_public_files)
    if with_private_files:
        restore_files(site, with_private_files)

    click.secho(f"🎉 Site {site} restored successfully!", fg="green")


def handle_encrypted_backup(sql_file_path, encryption_key):
    """Decrypt encrypted backup if required"""
    import frappe.utils.backups as backups

    err, out = frappe.utils.execute_in_shell(f"file {sql_file_path}", check_exit_code=True)
    if err:
        click.secho("❌ Failed to detect backup file type.", fg="red")
        sys.exit(1)

    if "AES" in out.decode().split(":")[-1].strip():
        click.secho("Encrypted backup detected. Decrypting...", fg="yellow")
        if not encryption_key:
            encryption_key = get_or_generate_backup_encryption_key()

        with decrypt_backup(sql_file_path, encryption_key):
            if not os.path.exists(sql_file_path):
                click.secho("❌ Decryption failed.", fg="red")
                sys.exit(1)
    return sql_file_path


def restore_database_with_progress(sql_file_path, site, db_root_username, db_root_password, db_name):
    """Restore DB using pv for real-time progress bar, supports .gz"""

    sql_file = Path(sql_file_path).resolve()
    if not sql_file.exists():
        click.secho(f"❌ SQL file {sql_file} not found.", fg="red")
        sys.exit(1)

    click.secho(f"⏳ Restoring database for {site}...", fg="cyan")

    # Check if compressed
    if str(sql_file).endswith(".gz"):
        cmd = f"pv {sql_file} | gunzip | mysql -u {db_root_username} -p'{db_root_password}' {db_name}"
    else:
        cmd = f"pv {sql_file} | mysql -u {db_root_username} -p'{db_root_password}' {db_name}"

    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        click.secho(f"❌ Database restore failed: {e}", fg="red")
        sys.exit(1)

    click.secho(f"✅ Database restored for {site}", fg="green")



def set_admin_password(site, admin_password=None):
    """Set Administrator password"""
    from frappe.utils.password import update_password

    if not admin_password:
        admin_password = getpass(f"Enter new Administrator password for {site}: ")
        confirm_password = getpass("Confirm password: ")
        if admin_password != confirm_password:
            click.secho("❌ Passwords do not match!", fg="red")
            sys.exit(1)

    frappe.connect()
    update_password(user="Administrator", pwd=admin_password, logout_all_sessions=True)
    frappe.db.commit()
    frappe.destroy()
    click.secho(f"🔑 Administrator password updated for {site}", fg="green")


def restore_files(site, tar_path):
    """Extract public/private files"""
    tar_path = Path(tar_path).resolve()
    if not tar_path.exists():
        click.secho(f"❌ File {tar_path} not found.", fg="red")
        return

    click.secho(f"⏳ Restoring files from {tar_path}...", fg="cyan")
    extract_files(site, str(tar_path))
    os.remove(tar_path)
    click.secho(f"✅ Files restored from {tar_path}", fg="green")


# Register the command
commands = [rest]
