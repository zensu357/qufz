package com.eta.afb;

import android.content.pm.ApplicationInfo;
import android.util.Log;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;
import io.github.libxposed.api.error.HookFailedError;

import java.io.File;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * 反诈上报阻断（AntiFraudBlock / libxposed API 102 版）
 *
 * 作用域：com.coloros.phonemanager（含 :remote / :scan / :card 等子进程）
 *
 * 实测链路（本机 PhoneManager 17.1.6 / ColorOS 16，类名未混淆）：
 *   1. com.oplus.phonemanager.aivoicecalldetect.utils.AiDetectStatistics
 *        反诈埋点封装：主开关点击、事件计数、推送触达、误报反馈、VOIP 白名单外应用
 *        最终都走 vf.l.r(ctx, "20092", <event>, map) -> xf.b.d(runnable) -> TrackApi.E
 *   2. com.oplus.phonemanager.aivoicecalldetect.utils.AiVoiceDetectDCSUtils
 *        云端 DCS 上报：号码、包名、通话时长、检测时长、判定码 —— 最敏感的一跳
 *        方法名随管家版本变（17.1.6 = m/n，16.17.3 混淆成 a~h），按 "static void" 全匹配；
 *        非 void（16.x a(String)->J 是 callId 时间戳映射）不动
 *   3. com.oplus.nearx.track.TrackApi
 *        appId="20092"，全部手机管家遥测的最终出口；sink 即 (String,String,Map)->V
 *        三参方法，17.1.6 叫 E、16.17.3 改名 O —— 按签名定位，不按方法名硬编码
 *
 * 保留不动（本地功能必须照常）：
 *   RiskWarningUtilsKt.insertFraudDetectSecurityEvent      -> 本地反诈记录落库
 *   FraudDetectNotificationHelperKt.showRiskNotification   -> 本地风险通知
 *   FraudRiskDialogActivity / FraudDetectNotificationHelperKt -> 本地弹窗
 *   AiVoiceDetectForegroundService / SecurityEventStatisticsVM -> 本地检测服务与记录页
 */
public class MainHook extends XposedModule {

    private static final String TAG = "AntiFraudBlock";
    private static final String PKG = "com.coloros.phonemanager";
    private static final String TRACK_APP_ID = "20092";

    /** 逃生阀：存在该文件则本次注入全部空转（改完 kill 掉手机管家即恢复默认行为） */
    private static final String KILL_SWITCH = "/data/local/tmp/afb.disable";

    private static boolean sDisabled = false;

    private static final String[] BLOCK_PREFIX = {"anti_fraud", "ai_detect", "fraud"};

    private static final Set<String> BLOCK_EXACT = new HashSet<>();

    static {
        BLOCK_EXACT.add("anti_fraud_switches");
        BLOCK_EXACT.add("anti_fraud_events_count");
        BLOCK_EXACT.add("anti_fraud_master_switche");
        BLOCK_EXACT.add("anti_fraud_handle_event");
        BLOCK_EXACT.add("anti_fraud_false_report_event");
        BLOCK_EXACT.add("ai_detect_result_event");
        BLOCK_EXACT.add("ai_detect_voip_app_outside_lists");
    }

    public MainHook() {
        super();
    }

    @Override
    public void onModuleLoaded(XposedModuleInterface.ModuleLoadedParam param) {
        log("module loaded, api=" + getApiVersion() + " framework=" + getFrameworkName());
    }

    @Override
    public void onPackageLoaded(XposedModuleInterface.PackageLoadedParam param) {
        String pkg = param.getPackageName();
        if (pkg == null || !pkg.startsWith(PKG)) return;

        sDisabled = new File(KILL_SWITCH).exists();
        log("attach " + pkg + (sDisabled ? " (kill switch ON, no-op)" : ""));

        ClassLoader cl = param.getDefaultClassLoader();

        // 1) 反诈埋点封装：所有 static void 全短路（返回 String 的 a(ZZZ) 不动）
        hookStaticVoid(cl,
                "com.oplus.phonemanager.aivoicecalldetect.utils.AiDetectStatistics", null);

        // 2) DCS 云端上报：全部 static void 短路（17.x 的 m/n、16.x 的 b~h 全覆盖；
        //    返回 J 的 a(String) 是 callId 时间戳映射，不是 void，天然排除）
        hookStaticVoid(cl,
                "com.oplus.phonemanager.aivoicecalldetect.utils.AiVoiceDetectDCSUtils", null);

        // 3) 最终出口兜底：TrackApi 的 (String,String,Map)->V sink（17.x=E，16.x=O），
        //    appId="20092" 且事件名命中黑名单的直接吞
        hookTrackSink(cl);

        log("kept local: insertFraudDetectSecurityEvent / showRiskNotification / FraudRiskDialogActivity");
    }

    @SuppressWarnings("unused")
    private void hookStaticVoid(ClassLoader cl, String clsName, final Set<String> names) {
        try {
            Class<?> c = Class.forName(clsName, false, cl);
            int hit = 0;
            for (final Method m : c.getDeclaredMethods()) {
                if (!Modifier.isStatic(m.getModifiers())) continue;
                if (m.getReturnType() != void.class) continue;
                if (names != null && !names.contains(m.getName())) continue;
                hookMethod(m, "silence " + clsName + "#" + m.getName() + "/" + m.getParameterTypes().length, true);
                hit++;
            }
            log(clsName + " -> " + hit + " method(s) silenced");
        } catch (Throwable t) {
            log("hook class failed: " + clsName + " : " + t);
        }
    }

    @SuppressWarnings("unused")
    private void hookTrackSink(ClassLoader cl) {
        final String cls = "com.oplus.nearx.track.TrackApi";
        try {
            Class<?> c = Class.forName(cls, false, cl);
            int hit = 0;
            for (Method m : c.getDeclaredMethods()) {
                Class<?>[] ps = m.getParameterTypes();
                // sink 按形状找：17.x = E(String,String,Map)，16.x = N/O/P/Q 一族
                // （Map / JSONObject / 两参三种重载）。统一按"前两参 String 且返回 void"匹配，
                // 事件过滤在 intercept 里做，误伤不了别的 appId
                if (ps.length < 2) continue;
                if (ps[0] != String.class || ps[1] != String.class) continue;
                if (m.getReturnType() != void.class) continue;
                StringBuilder shape = new StringBuilder("(");
                for (Class<?> p : ps) shape.append(p.getSimpleName()).append(",");
                shape.setCharAt(shape.length() - 1, ')');
                hookMethod(m, "sink TrackApi#" + m.getName() + shape, null);
                hit++;
            }
            log("TrackApi sink -> " + hit + " hooked");
        } catch (Throwable t) {
            log("hook TrackApi failed: " + t);
        }
    }

    /**
     * @param always  true=无条件吞掉返回值；null=按事件名判定（仅 TrackApi.E 用）；false=不动
     */
    private void hookMethod(Executable exe, final String label, final Boolean always) {
        try {
            hook(exe).intercept(new XposedInterface.Hooker() {
                @Override
                public Object intercept(XposedInterface.Chain chain) throws Throwable {
                    if (sDisabled) return chain.proceed();
                    if (always == null) {
                        // TrackApi sink 判定分支：appId="20092" + 事件名命中黑名单才吞
                        // （16.x 同一事件会串行穿过 O->P->Q，在 O 层吞掉后下两层不再触发）
                        Object appId = chain.getArg(0);
                        Object ev = chain.getArg(1);
                        if (ev instanceof String
                                && TRACK_APP_ID.equals(String.valueOf(appId))
                                && isBlockedEvent((String) ev)) {
                            log("blocked track event: " + ev + " [" + label + "]");
                            return null;
                        }
                        return chain.proceed();
                    }
                    if (always) {
                        log("hit " + label);
                        return null;
                    }
                    return chain.proceed();
                }
            });
        } catch (HookFailedError e) {
            log("hook failed " + label + " : " + e);
        } catch (Throwable t) {
            log("hook error " + label + " : " + t);
        }
    }

    private static boolean isBlockedEvent(String ev) {
        if (ev == null || ev.isEmpty()) return false;
        if (BLOCK_EXACT.contains(ev)) return true;
        String low = ev.toLowerCase(Locale.ROOT);
        for (String p : BLOCK_PREFIX) {
            if (low.startsWith(p)) return true;
        }
        return false;
    }

    private void log(String s) {
        try {
            Log.i(TAG, s);
        } catch (Throwable ignore) {
        }
        try {
            this.log(4, TAG, s);
        } catch (Throwable ignore) {
        }
    }
}
