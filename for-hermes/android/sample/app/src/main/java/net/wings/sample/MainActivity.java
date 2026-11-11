package net.wings.sample;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.journeyapps.barcodescanner.ScanContract;
import com.journeyapps.barcodescanner.ScanOptions;

import net.wings.tunnel.WingsTunnel;

import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Scan a Wings code, give Android's VPN consent, connect, and show the state. Nothing more. */
public class MainActivity extends AppCompatActivity {

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());

    private WingsTunnel tunnel;
    private File pairingFile;
    private WingsTunnel.Pairing pairing;
    private TextView status;
    private Button action;
    private final Runnable ticker = new Runnable() {
        @Override
        public void run() {
            showStats();
            ui.postDelayed(this, 2000);
        }
    };

    private final ActivityResultLauncher<ScanOptions> scanner =
            registerForActivityResult(new ScanContract(), r -> {
                if (r.getContents() != null) onScanned(r.getContents());
            });

    private final ActivityResultLauncher<Intent> consent =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), r -> {
                if (r.getResultCode() == RESULT_OK) connect();
                else show("Android needs your OK to start the tunnel.");
            });

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        tunnel = WingsTunnel.get(this);
        pairingFile = WingsTunnel.defaultPairingFile(this);
        pairing = WingsTunnel.loadPairing(pairingFile);
        tunnel.setStateListener(s -> ui.post(this::refresh));

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        int pad = Math.round(24 * getResources().getDisplayMetrics().density);
        col.setPadding(pad, pad * 2, pad, pad);
        status = new TextView(this);
        status.setTextSize(18);
        action = new Button(this);
        action.setAllCaps(false);
        action.setOnClickListener(v -> onAction());
        col.addView(status);
        col.addView(action);
        setContentView(col);
        refresh();
        ui.postDelayed(ticker, 2000);
    }

    @Override
    protected void onDestroy() {
        ui.removeCallbacksAndMessages(null);
        tunnel.setStateListener(null);
        worker.shutdown();
        super.onDestroy();
    }

    private void onAction() {
        if (pairing == null) {
            ScanOptions o = new ScanOptions();
            o.setDesiredBarcodeFormats(ScanOptions.QR_CODE);
            o.setPrompt("Scan the Wings code");
            o.setBeepEnabled(false);
            scanner.launch(o);
        } else if (tunnel.state() == WingsTunnel.State.UP) {
            worker.execute(() -> {
                tunnel.disconnect();
                ui.post(this::refresh);
            });
        } else {
            askThenConnect();
        }
    }

    private void onScanned(String text) {
        try {
            pairing = WingsTunnel.parse(text);
            WingsTunnel.savePairing(pairing, pairingFile);
        } catch (WingsTunnel.PairingException e) {
            show(e.getMessage());
            return;
        } catch (Exception e) {
            show("Could not save the code.");
            return;
        }
        askThenConnect();
    }

    private void askThenConnect() {
        Intent i = WingsTunnel.consentIntent(this);
        if (i != null) consent.launch(i);
        else connect();
    }

    private void connect() {
        show("Connecting...");
        final WingsTunnel.Pairing p = pairing;
        worker.execute(() -> {
            try {
                tunnel.connect(p);
                ui.post(this::refresh);
            } catch (Exception e) {
                ui.post(() -> show("Could not connect. Is another VPN locked on?"));
            }
        });
    }

    private void refresh() {
        if (pairing == null) {
            show("No Wings code yet.");
            action.setText("Scan Wings code");
            return;
        }
        boolean up = tunnel.state() == WingsTunnel.State.UP;
        action.setText(up ? "Disconnect" : "Connect");
        if (!up) show("Not connected.\nThis phone: " + pairing.deviceAddress());
        else showStats();
    }

    private void showStats() {
        if (pairing != null && tunnel.state() == WingsTunnel.State.UP) {
            WingsTunnel.Stats s = tunnel.stats();
            String link = s == null ? "" : s.isReachable(System.currentTimeMillis())
                    ? "Always-on machine answered " + (System.currentTimeMillis() - s.lastHandshakeMillis) / 1000 + " s ago"
                    : "Waiting for the hub to answer";
            String bytes = s == null ? "" : "\nIn " + s.rxBytes + " B, out " + s.txBytes + " B";
            String url = pairing.hermesUrl();
            show("Connected.\nThis phone: " + pairing.deviceAddress()
                    + "\nAlways-on machine: " + pairing.hubAddress()
                    + "\n" + link + bytes
                    + (url != null ? "\nHermes: " + url : "\nAdd http://<name>.wings in Hermes"));
        }
    }

    private void show(String s) {
        status.setText(s);
    }
}
