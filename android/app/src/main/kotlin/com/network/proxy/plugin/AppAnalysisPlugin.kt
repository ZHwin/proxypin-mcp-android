package com.network.proxy.plugin

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.content.pm.Signature
import android.os.Build
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * 应用分析插件：应用列表、应用元数据（权限/组件/签名证书）、APK 导出
 * 供 MCP Server 使用，支持 AI 客户端获取并分析设备上安装的应用，无需 root
 */
class AppAnalysisPlugin : AndroidFlutterPlugin() {
    private var channel: MethodChannel? = null

    companion object {
        const val CHANNEL = "com.proxy/appAnalysis"
        private const val EXPORT_DIR = "apk_export"

        /** 组件列表每类最多导出条数，避免元数据过大 */
        private const val MAX_COMPONENTS = 200

        /** PackageInfo.REQUESTED_PERMISSION_REQUIRED（等值字面量，避免 SDK 常量可见性问题） */
        private const val REQ_PERM_REQUIRED = 0x00000001

        /** PackageInfo.REQUESTED_PERMISSION_GRANTED */
        private const val REQ_PERM_GRANTED = 0x00000002
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, CHANNEL)
        channel!!.setMethodCallHandler { call, result ->
            Thread {
                try {
                    when (call.method) {
                        "listApps" -> {
                            val includeSystem = call.argument<Boolean>("includeSystem") ?: false
                            val keyword = call.argument<String>("keyword") ?: ""
                            result.success(listApps(includeSystem, keyword))
                        }

                        "getAppMetadata" -> {
                            val packageName = call.argument<String>("packageName") ?: ""
                            result.success(getAppMetadata(packageName))
                        }

                        "exportApk" -> {
                            val packageName = call.argument<String>("packageName") ?: ""
                            val includeSplits = call.argument<Boolean>("includeSplits") ?: false
                            result.success(exportApk(packageName, includeSplits))
                        }

                        else -> result.notImplemented()
                    }
                } catch (e: PackageManager.NameNotFoundException) {
                    result.error("APP_NOT_FOUND", e.message, null)
                } catch (e: Exception) {
                    result.error("APP_ANALYSIS_ERROR", e.message, null)
                }
            }.start()
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 应用列表
    // ─────────────────────────────────────────────────────────────

    private fun listApps(includeSystem: Boolean, keyword: String): List<Map<String, Any?>> {
        val pm = activity.packageManager
        val apps = pm.getInstalledApplications(0)
            .filter { includeSystem || (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }

        val kw = keyword.trim().lowercase(Locale.ENGLISH)
        val dateFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

        return apps.mapNotNull { app ->
            try {
                val label = pm.getApplicationLabel(app).toString()
                val pkg = app.packageName
                if (kw.isNotEmpty() &&
                    !pkg.lowercase(Locale.ENGLISH).contains(kw) &&
                    !label.lowercase(Locale.ENGLISH).contains(kw)
                ) {
                    return@mapNotNull null
                }
                val pkgInfo = pm.getPackageInfo(pkg, 0)
                mapOf(
                    "packageName" to pkg,
                    "name" to label,
                    "versionName" to (pkgInfo.versionName ?: ""),
                    "versionCode" to versionCode(pkgInfo),
                    "isSystem" to ((app.flags and ApplicationInfo.FLAG_SYSTEM) != 0),
                    "enabled" to app.enabled,
                    "debuggable" to ((app.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0),
                    "apkSize" to apkTotalSize(pkgInfo),
                    "splitCount" to (app.splitSourceDirs?.size ?: 0),
                    "installTime" to dateFmt.format(Date(pkgInfo.firstInstallTime)),
                    "updateTime" to dateFmt.format(Date(pkgInfo.lastUpdateTime)),
                )
            } catch (e: Exception) {
                null
            }
        }.sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { (it["name"] as? String).orEmpty() })
    }

    // ─────────────────────────────────────────────────────────────
    // 应用元数据
    // ─────────────────────────────────────────────────────────────

    private fun getAppMetadata(packageName: String): Map<String, Any?> {
        if (packageName.isBlank()) {
            throw IllegalArgumentException("packageName 不能为空")
        }
        val pm = activity.packageManager
        var flags = PackageManager.GET_PERMISSIONS or
                PackageManager.GET_ACTIVITIES or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS or
                PackageManager.GET_PROVIDERS or
                PackageManager.GET_META_DATA or
                PackageManager.GET_SIGNING_CERTIFICATES
        if (Build.VERSION.SDK_INT < 28) {
            @Suppress("DEPRECATION")
            flags = flags or PackageManager.GET_SIGNATURES
        }
        val pkgInfo = pm.getPackageInfo(packageName, flags)
        val app = pkgInfo.applicationInfo
            ?: throw PackageManager.NameNotFoundException("未找到应用 $packageName")

        val dateFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        val result = linkedMapOf<String, Any?>()

        // 基础信息
        result["packageName"] = packageName
        result["name"] = pm.getApplicationLabel(app).toString()
        result["versionName"] = pkgInfo.versionName
        result["versionCode"] = versionCode(pkgInfo)
        result["enabled"] = app.enabled
        result["debuggable"] = (app.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        result["isSystemApp"] = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        result["isUpdatedSystemApp"] = (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        result["hasCode"] = (app.flags and ApplicationInfo.FLAG_HAS_CODE) != 0
        result["allowBackup"] = (app.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0
        if (Build.VERSION.SDK_INT >= 24) {
            result["minSdkVersion"] = app.minSdkVersion
            result["targetSdkVersion"] = app.targetSdkVersion
        }
        @Suppress("DEPRECATION")
        result["sharedUserId"] = pkgInfo.sharedUserId
        result["uid"] = app.uid
        result["processName"] = app.processName
        result["installTime"] = dateFmt.format(Date(pkgInfo.firstInstallTime))
        result["updateTime"] = dateFmt.format(Date(pkgInfo.lastUpdateTime))

        // APK 信息
        result["apkPath"] = app.sourceDir
        result["splitApkPaths"] = app.splitSourceDirs?.toList()
        result["splitCount"] = app.splitSourceDirs?.size ?: 0
        result["apkSize"] = apkTotalSize(pkgInfo)
        result["launcherActivity"] = try {
            pm.getLaunchIntentForPackage(packageName)?.component?.className
        } catch (e: Exception) {
            null
        }

        // 权限列表（含保护级别）
        result["permissions"] = formatPermissions(pm, pkgInfo)

        // 四大组件
        result["activities"] = formatComponents(
            pkgInfo.activities?.size ?: 0,
            pkgInfo.activities?.map { componentInfo(it.name, it.exported, it.permission) })
        result["services"] = formatComponents(
            pkgInfo.services?.size ?: 0,
            pkgInfo.services?.map { componentInfo(it.name, it.exported, it.permission) })
        result["receivers"] = formatComponents(
            pkgInfo.receivers?.size ?: 0,
            pkgInfo.receivers?.map { componentInfo(it.name, it.exported, it.permission) })
        result["providers"] = formatComponents(
            pkgInfo.providers?.size ?: 0,
            pkgInfo.providers?.map {
                mapOf(
                    "name" to it.name,
                    "exported" to it.exported,
                    "authorities" to it.authority,
                    "readPermission" to it.readPermission,
                    "writePermission" to it.writePermission,
                )
            })

        // 签名证书
        result["signatures"] = formatSignatures(pkgInfo)

        // manifest meta-data（渠道号、SDK 配置等）
        result["metaData"] = app.metaData?.keySet()?.associateWith { key ->
            app.metaData.get(key)?.toString()
        } ?: emptyMap<String, String>()

        return result
    }

    private fun versionCode(pkgInfo: PackageInfo): Long =
        if (Build.VERSION.SDK_INT >= 28) pkgInfo.longVersionCode
        else @Suppress("DEPRECATION") pkgInfo.versionCode.toLong()

    private fun apkTotalSize(pkgInfo: PackageInfo): Long {
        val app = pkgInfo.applicationInfo ?: return 0
        var size = 0L
        try {
            size += File(app.sourceDir).length()
            app.splitSourceDirs?.forEach { size += File(it).length() }
        } catch (e: Exception) {
        }
        return size
    }

    private fun formatPermissions(pm: PackageManager, pkgInfo: PackageInfo): List<Map<String, Any?>> {
        val permissions = pkgInfo.requestedPermissions ?: return emptyList()
        val permFlags = pkgInfo.requestedPermissionsFlags
        return permissions.mapIndexed { index, perm ->
            val entry = mutableMapOf<String, Any?>(
                "name" to perm,
                "required" to (permFlags == null || index >= permFlags.size ||
                        (permFlags[index] and REQ_PERM_REQUIRED) != 0),
                "granted" to (permFlags != null && index < permFlags.size &&
                        (permFlags[index] and REQ_PERM_GRANTED) != 0),
            )
            try {
                val pi = pm.getPermissionInfo(perm, 0)
                val base = pi.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE
                entry["protectionLevel"] = when (base) {
                    PermissionInfo.PROTECTION_NORMAL -> "normal"
                    PermissionInfo.PROTECTION_DANGEROUS -> "dangerous"
                    PermissionInfo.PROTECTION_SIGNATURE -> "signature"
                    PermissionInfo.PROTECTION_INTERNAL -> "internal"
                    else -> "unknown"
                }
                val flagList = mutableListOf<String>()
                if ((pi.protectionLevel and PermissionInfo.PROTECTION_FLAG_PRIVILEGED) != 0) flagList.add("privileged")
                if ((pi.protectionLevel and PermissionInfo.PROTECTION_FLAG_PRE23) != 0) flagList.add("pre23")
                if ((pi.protectionLevel and PermissionInfo.PROTECTION_FLAG_PREINSTALLED) != 0) flagList.add("preinstalled")
                if ((pi.protectionLevel and PermissionInfo.PROTECTION_FLAG_APPOP) != 0) flagList.add("appop")
                if (flagList.isNotEmpty()) entry["protectionFlags"] = flagList
                pi.loadDescription(pm)?.toString()?.let { entry["description"] = it }
            } catch (e: Exception) {
                entry["protectionLevel"] = "unknown"
            }
            entry
        }
    }

    private fun componentInfo(name: String, exported: Boolean, permission: String?): Map<String, Any?> =
        mutableMapOf<String, Any?>("name" to name, "exported" to exported).apply {
            if (!permission.isNullOrBlank()) this["permission"] = permission
        }

    private fun formatComponents(total: Int, components: List<Map<String, Any?>>?): Map<String, Any?> {
        val list = components ?: emptyList()
        return mapOf(
            "total" to total,
            "truncated" to (list.size > MAX_COMPONENTS),
            "items" to list.take(MAX_COMPONENTS),
        )
    }

    private fun formatSignatures(pkgInfo: PackageInfo): List<Map<String, Any?>> {
        val signatures: Array<Signature> = if (Build.VERSION.SDK_INT >= 28) {
            val si = pkgInfo.signingInfo
            when {
                si == null -> emptyArray()
                si.hasMultipleSigners() -> si.apkContentsSigners ?: emptyArray()
                else -> si.signingCertificateHistory ?: emptyArray()
            }
        } else {
            @Suppress("DEPRECATION") pkgInfo.signatures ?: emptyArray()
        }
        return signatures.take(5).map { sig -> signatureInfo(sig) }
    }

    private fun signatureInfo(sig: Signature): Map<String, Any?> {
        val bytes = sig.toByteArray()
        fun hex(digest: ByteArray) = digest.joinToString("") { "%02x".format(it) }
        val dateFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

        val certInfo = try {
            val cf = CertificateFactory.getInstance("X.509")
            val cert = cf.generateCertificate(bytes.inputStream()) as X509Certificate
            mapOf(
                "subject" to cert.subjectX500Principal.name,
                "issuer" to cert.issuerX500Principal.name,
                "serialNumber" to cert.serialNumber.toString(16),
                "notBefore" to dateFmt.format(cert.notBefore),
                "notAfter" to dateFmt.format(cert.notAfter),
                "signatureAlgorithm" to cert.sigAlgName,
            )
        } catch (e: Exception) {
            null
        }

        return mapOf(
            "md5" to hex(MessageDigest.getInstance("MD5").digest(bytes)),
            "sha1" to hex(MessageDigest.getInstance("SHA-1").digest(bytes)),
            "sha256" to hex(MessageDigest.getInstance("SHA-256").digest(bytes)),
            "certificate" to certInfo,
        )
    }

    // ─────────────────────────────────────────────────────────────
    // APK 导出（无需 root：APK 文件对可查询应用可读）
    // ─────────────────────────────────────────────────────────────

    private fun exportApk(packageName: String, includeSplits: Boolean): Map<String, Any?> {
        if (packageName.isBlank()) {
            throw IllegalArgumentException("packageName 不能为空")
        }
        val pm = activity.packageManager
        val app = pm.getApplicationInfo(packageName, 0)
        val baseApk = File(app.sourceDir)
        if (!baseApk.exists()) {
            throw IllegalArgumentException("APK 文件不存在: ${app.sourceDir}")
        }

        val exportDir = File(activity.cacheDir, EXPORT_DIR)
        if (!exportDir.exists()) exportDir.mkdirs()

        val safeName = packageName.replace(Regex("[^A-Za-z0-9_]"), "_")
        val outFile: File
        if (includeSplits && !app.splitSourceDirs.isNullOrEmpty()) {
            // 所有 split 打包为 zip
            outFile = File(exportDir, "${safeName}_splits.zip")
            ZipOutputStream(outFile.outputStream().buffered()).use { zip ->
                zip.putNextEntry(ZipEntry(baseApk.name))
                baseApk.inputStream().use { it.copyTo(zip) }
                zip.closeEntry()
                app.splitSourceDirs!!.forEach { splitPath ->
                    val f = File(splitPath)
                    if (f.exists()) {
                        zip.putNextEntry(ZipEntry(f.name))
                        f.inputStream().use { it.copyTo(zip) }
                        zip.closeEntry()
                    }
                }
            }
        } else {
            outFile = File(exportDir, "${safeName}_base.apk")
            baseApk.inputStream().use { input ->
                outFile.outputStream().use { input.copyTo(it) }
            }
        }

        return mapOf(
            "packageName" to packageName,
            "path" to outFile.absolutePath,
            "fileName" to outFile.name,
            "size" to outFile.length(),
            "baseApkPath" to baseApk.absolutePath,
            "splitCount" to (app.splitSourceDirs?.size ?: 0),
            "includeSplits" to includeSplits,
        )
    }
}
