# Access (optional)

Off by default. Enable with the feature `Access`:

```powershell
./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -Features Hunting,Indicators,Agents,Access
```

- Who holds which admin role – **active**, **eligible via PIM** or **requestable via access packages**
- Paths: direct, via group, via PIM for groups, via access package (also when the package grants a group that holds a role)
- Entra ID roles (including administrative unit scopes) and Intune RBAC
- **Who can do what?** – search by role or permission (e.g. `microsoft.directory/users/password/update`)
- **My access** for every employee – their own roles with links to PIM and My Access

Large groups are capped at 10,000 members when resolving (`WL_MAX_GROUP_MEMBERS`).
