package com.example.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ClearAll
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.core.assets.ExtractedBinary
import com.example.core.shell.ExecutionMode
import com.example.core.verifier.CrossVerificationSummary
import com.example.data.local.VerificationAlertEntity
import com.example.ui.TerminalLogEntry

@Composable
fun TopSystemStatusBar(
    executionMode: ExecutionMode,
    isRootAvailable: Boolean,
    isBusy: Boolean,
    activeTaskTitle: String,
    binaries: List<ExtractedBinary>,
    verificationSummary: CrossVerificationSummary?,
    alerts: List<VerificationAlertEntity>,
    onToggleMode: (ExecutionMode) -> Unit,
    onRunVerifier: () -> Unit
) {
    var showBinariesPanel by remember { mutableStateOf(false) }
    var showAlertsPanel by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(horizontal = 16.dp, vertical = 10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(38.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(MaterialTheme.colorScheme.primaryContainer),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Memory,
                        contentDescription = "ROM Forge Engine",
                        tint = MaterialTheme.colorScheme.primary
                    )
                }
                Spacer(modifier = Modifier.width(10.dp))
                Column {
                    Text(
                        text = "ROM FORGE • AOSP KITCHEN",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.ExtraBold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        text = "Reverse-Compiler ARM64 • 100% Offline",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // Cross-Verifier Score Badge
            val score = verificationSummary?.score ?: 100
            val scoreColor = when {
                score >= 90 -> MaterialTheme.colorScheme.secondary
                score >= 70 -> MaterialTheme.colorScheme.tertiary
                else -> MaterialTheme.colorScheme.error
            }
            Surface(
                modifier = Modifier
                    .clip(RoundedCornerShape(12.dp))
                    .clickable { showAlertsPanel = !showAlertsPanel }
                    .testTag("verifier_score_badge"),
                color = scoreColor.copy(alpha = 0.14f),
                shape = RoundedCornerShape(12.dp)
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = if (score >= 85) Icons.Default.VerifiedUser else Icons.Default.Warning,
                        contentDescription = "Intégrité ROM",
                        tint = scoreColor,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "Audit $score%",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = scoreColor
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Hybrid Mode Selector + Static Binaries Pill
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = executionMode == ExecutionMode.NON_ROOT_USERSPACE,
                onClick = { onToggleMode(ExecutionMode.NON_ROOT_USERSPACE) },
                label = {
                    Text(
                        text = "Non-Root (SAF / Userspace)",
                        style = MaterialTheme.typography.labelSmall
                    )
                },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                },
                modifier = Modifier.testTag("mode_non_root_chip")
            )

            FilterChip(
                selected = executionMode == ExecutionMode.ROOT_LOOPBACK,
                onClick = { onToggleMode(ExecutionMode.ROOT_LOOPBACK) },
                label = {
                    Text(
                        text = if (isRootAvailable) "Root (Loopback RW)" else "Root (Simulé / Loop)",
                        style = MaterialTheme.typography.labelSmall
                    )
                },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Default.Build,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                },
                modifier = Modifier.testTag("mode_root_chip")
            )

            Spacer(modifier = Modifier.weight(1f))

            AssistChip(
                onClick = { showBinariesPanel = !showBinariesPanel },
                label = {
                    Text(
                        text = "${binaries.size} Binaires ARM64",
                        style = MaterialTheme.typography.labelSmall
                    )
                },
                colors = AssistChipDefaults.assistChipColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                ),
                modifier = Modifier.testTag("binaries_inspect_chip")
            )
        }

        if (isBusy) {
            Spacer(modifier = Modifier.height(6.dp))
            LinearProgressIndicator(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(4.dp)
                    .clip(RoundedCornerShape(2.dp))
            )
            if (activeTaskTitle.isNotEmpty()) {
                Text(
                    text = activeTaskTitle,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
        }

        // Expandable Static ARM64 Binaries Drawer
        AnimatedVisibility(visible = showBinariesPanel) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)
                )
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(
                        text = "Outils Natifs Statiques Extraits (context.filesDir/bin - chmod 0755)",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    binaries.forEach { bin ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 3.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "${bin.name} (SHA256: ${bin.sha256})",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Text(
                                    text = bin.description,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Text(
                                text = if (bin.executable) "EXEC 0755" else "RO",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.secondary,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }
        }

        // Expandable Intelligent Cross-Verifier Alerts Drawer
        AnimatedVisibility(visible = showAlertsPanel) {
            ElevatedCard(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp)
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Analyseur & Vérificateur Croisé AOSP",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        AssistChip(
                            onClick = onRunVerifier,
                            label = { Text("Relancer l'Audit", style = MaterialTheme.typography.labelSmall) },
                            modifier = Modifier.testTag("re_run_verifier_button")
                        )
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    alerts.forEach { alert ->
                        val badgeColor = when (alert.severity) {
                            "CRITICAL" -> MaterialTheme.colorScheme.error
                            "WARNING" -> MaterialTheme.colorScheme.tertiary
                            else -> MaterialTheme.colorScheme.secondary
                        }
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(badgeColor.copy(alpha = 0.08f))
                                .padding(8.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Icon(
                                imageVector = if (alert.severity == "PASS") Icons.Default.CheckCircle else Icons.Default.Warning,
                                contentDescription = alert.severity,
                                tint = badgeColor,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "[${alert.module}] ${alert.title}",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = badgeColor
                                )
                                Text(
                                    text = alert.technicalDetail,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                if (!alert.resolved) {
                                    Text(
                                        text = "Action : ${alert.remediationCommand}",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun IntegratedTerminalConsole(
    logs: List<TerminalLogEntry>,
    isExpanded: Boolean,
    onToggleExpand: () -> Unit,
    onClear: () -> Unit
) {
    val listState = rememberLazyListState()

    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) {
            listState.animateScrollToItem(logs.lastIndex)
        }
    }

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .border(
                width = 1.dp,
                color = MaterialTheme.colorScheme.outlineVariant,
                shape = RoundedCornerShape(topStart = 14.dp, topEnd = 14.dp)
            ),
        color = Color(0xFF090D16),
        shape = RoundedCornerShape(topStart = 14.dp, topEnd = 14.dp)
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            // Terminal Header Bar
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onToggleExpand() }
                    .padding(horizontal = 12.dp, vertical = 6.dp)
                    .testTag("terminal_toggle_header"),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(Color(0xFF10B981))
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Icon(
                        imageVector = Icons.Default.Terminal,
                        contentDescription = "Terminal",
                        tint = Color(0xFF00E5FF),
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "SHELL & REVERSE-COMPILER LOGS (${logs.size})",
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFE2E8F0)
                    )
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconButton(
                        onClick = onClear,
                        modifier = Modifier
                            .size(32.dp)
                            .testTag("clear_terminal_button")
                    ) {
                        Icon(
                            imageVector = Icons.Default.ClearAll,
                            contentDescription = "Effacer les logs",
                            tint = Color(0xFF94A3B8),
                            modifier = Modifier.size(18.dp)
                        )
                    }
                    Icon(
                        imageVector = if (isExpanded) Icons.Default.ExpandMore else Icons.Default.ExpandLess,
                        contentDescription = "Agrandir ou réduire le terminal",
                        tint = Color(0xFF94A3B8)
                    )
                }
            }

            // Live Log Stream
            val consoleHeight = if (isExpanded) 210.dp else 74.dp
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(consoleHeight)
                    .padding(horizontal = 12.dp, vertical = 4.dp)
            ) {
                items(logs, key = { it.id }) { entry ->
                    val lineColor = when (entry.level) {
                        "ERROR" -> Color(0xFFF87171)
                        "WARN" -> Color(0xFFFBBF24)
                        "SUCCESS" -> Color(0xFF34D399)
                        else -> Color(0xFF93C5FD)
                    }
                    Text(
                        text = "${entry.timestamp} ${entry.message}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        lineHeight = 15.sp,
                        color = lineColor,
                        maxLines = if (isExpanded) 4 else 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}
