<script lang="ts">
	import { page } from '$app/stores';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api, type Investigation, type InvestigationTimelineEvent } from '$lib/api/client';
	import { addToast, isCustomerScope } from '$lib/stores';
	import { formatStatus, formatPhase, formatSeverity, formatDecision, formatDuration, formatEventType } from '$lib/utils/formatters';
	import ChatPanel from '$lib/components/chat/ChatPanel.svelte';

	let chatOpen = false;

	let investigation: Investigation | null = null;
	let events: InvestigationTimelineEvent[] = [];
	let loading = true;
	let eventsLoading = true;
	let error: string | null = null;
	let actionLoading = false;
	let showCancelModal = false;
	let cancelReason = '';
	let expandedEvents: Set<string> = new Set();
	let copiedLogId: string | null = null;
	let eventViewMode: Record<string, 'table' | 'json'> = {};

	// Safe reactive extraction for Jira Key and SOP Verdict without in-template TypeScript casting
	$: jiraIssueKey = (investigation as Record<string, any> | null)?.jira_issue_key;
	$: sopVerdict = (investigation as Record<string, any> | null)?.sop_verdict 
		|| (investigation as Record<string, any> | null)?.enrichments?.sop_verdict 
		|| (investigation as Record<string, any> | null)?.verdict?.sop_verdict;

	// Reactive OODA Pipeline Stage Determination
	$: oodaStages = (() => {
		if (!investigation) return [];
		const status = investigation.status || '';
		const phase = (investigation.phase || '').toLowerCase();
		const hasObservables = (investigation.observable_count || 0) > 0;
		const hasVerdict = Boolean(investigation.verdict_decision || sopVerdict || (investigation as Record<string, any> | null)?.verdict);
		const isActDone = ['closed', 'auto_closed', 'auto_closed_fp', 'closed_fp', 'closed_tp', 'escalated'].includes(status) 
			|| Boolean((investigation as Record<string, any> | null)?.thehive_case_id || jiraIssueKey);

		return [
			{
				step: '1',
				name: 'Observe',
				title: 'Telemetry & Asset Context',
				isDone: true,
				isActive: phase === 'observe' || phase === 'triage'
			},
			{
				step: '2',
				name: 'Orient',
				title: 'Threat Intel & Artifacts',
				isDone: hasObservables || ['orient', 'analysis', 'investigating'].includes(phase) || hasVerdict,
				isActive: phase === 'orient' || phase === 'analysis' || phase === 'investigating'
			},
			{
				step: '3',
				name: 'Decide',
				title: 'LangGraph Reasoning & SOP',
				isDone: hasVerdict,
				isActive: phase === 'decide' || phase === 'verdict'
			},
			{
				step: '4',
				name: 'Act',
				title: 'TheHive & Ticket Dispatch',
				isDone: isActDone,
				isActive: phase === 'act' || phase === 'remediation' || status === 'escalated'
			}
		];
	})();

	function getEventKey(event: InvestigationTimelineEvent, index: number): string {
		return event.id || (event as Record<string, any>).event_id || String(index);
	}

	function toggleEventDetails(key: string) {
		if (expandedEvents.has(key)) {
			expandedEvents.delete(key);
		} else {
			expandedEvents.add(key);
		}
		expandedEvents = new Set(expandedEvents);
	}

	function setViewMode(key: string, mode: 'table' | 'json') {
		eventViewMode = { ...eventViewMode, [key]: mode };
	}

	interface MetadataRow {
		key: string;
		value: string;
	}

	function getStructuredMetadata(data: Record<string, unknown> | undefined): MetadataRow[] {
		if (!data) return [];
		const rows: MetadataRow[] = [];

		function flatten(obj: Record<string, unknown>, prefix = '') {
			for (const [k, v] of Object.entries(obj)) {
				if (k === 'full_log' || k === 'raw_log') continue;
				
				if (k === 'raw' && typeof v === 'object' && v !== null && 'full_log' in (v as Record<string, unknown>)) {
					const { full_log, ...restRaw } = v as Record<string, unknown>;
					if (Object.keys(restRaw).length > 0) {
						flatten(restRaw, prefix ? `${prefix}.${k}` : k);
					}
					continue;
				}

				const fieldKey = prefix ? `${prefix}.${k}` : k;
				if (v === null || v === undefined) {
					rows.push({ key: fieldKey, value: 'null' });
				} else if (Array.isArray(v)) {
					const valStr = v.map((item) => (typeof item === 'object' && item !== null ? JSON.stringify(item) : String(item))).join(', ');
					rows.push({ key: fieldKey, value: valStr || '[]' });
				} else if (typeof v === 'object') {
					flatten(v as Record<string, unknown>, fieldKey);
				} else {
					rows.push({ key: fieldKey, value: String(v) });
				}
			}
		}

		flatten(data);
		return rows;
	}

	function copyToClipboard(text: string, id: string) {
		navigator.clipboard.writeText(text);
		copiedLogId = id;
		addToast({ type: 'success', message: 'Copied to clipboard!' });
		setTimeout(() => {
			if (copiedLogId === id) copiedLogId = null;
		}, 2500);
	}

	function extractRawLog(data: Record<string, unknown> | undefined): string {
		if (!data) return '';
		if (data.full_log) return String(data.full_log);
		if (data.raw_log) return String(data.raw_log);
		if (data.raw) {
			if (typeof data.raw === 'object' && data.raw !== null && 'full_log' in (data.raw as Record<string, unknown>)) {
				const rawObj = data.raw as Record<string, unknown>;
				if (rawObj.full_log) return String(rawObj.full_log);
			}
			return typeof data.raw === 'string' ? data.raw : JSON.stringify(data.raw, null, 2);
		}
		return '';
	}

	function formatEventSummary(eventType: string, data: Record<string, unknown>): string {
		switch (eventType) {
			case 'alert_ingested':
			case 'alert.ingested':
			case 'alert.added': {
				let titleText = String(data.rule_description || data.description || data.title || '');
				const isRawLog = !titleText || titleText === data.full_log || /^\d{4}-\d{2}-\d{2}/.test(titleText);
				
				if (isRawLog) {
					titleText = data.rule_id ? `Rule ${data.rule_id}` : 'Wazuh Alert';
				}
				
				const firedTimes = data.fired_times || data.firedtimes || (data.raw as Record<string, any> | undefined)?.firedtimes;
				const burstCount = firedTimes && Number(firedTimes) > 1 
					? ` (${firedTimes}x bursts)` 
					: (data.event_count && Number(data.event_count) > 1 ? ` (${data.event_count} events coalesced)` : '');
				
				return `Alert Ingested: ${titleText}${burstCount}`;
			}
			case 'investigation.created':
				return `Investigation started: "${data.title || 'Untitled'}"`;
			case 'investigation.started':
				return `Investigation began in ${formatPhase(data.phase as string) || 'Triage'} phase`;
			case 'investigation.closed':
				return `Investigation closed`;
			case 'investigation.paused':
				return `Investigation paused`;
			case 'investigation.resumed':
				return `Investigation resumed`;
			case 'investigation.cancelled':
				return `Investigation cancelled${data.reason ? `: ${data.reason}` : ''}`;
			case 'investigation.escalated':
				return `Investigation escalated to incident response`;
			case 'investigation.auto_closed':
				return `Investigation auto-closed (no threats found)`;
			case 'alert.correlated':
				return `Alert correlated: ${data.description || data.alert_id || 'Unknown alert'}`;
			case 'observable.extracted':
				return `Found ${data.observable_type}: ${data.observable_value}`;
			case 'enrichment.requested':
				return `Enrichment requested from ${data.enrichment_type || 'external source'}`;
			case 'enrichment.completed': {
				const result = data.result as Record<string, number> | undefined;
				if (result && typeof result.malicious === 'number') {
					return `${data.enrichment_type}: ${result.malicious} malicious, ${result.suspicious || 0} suspicious detections for ${data.observable_value}`;
				}
				return `Enrichment completed for ${data.observable_value}`;
			}
			case 'enrichment.failed':
				return `Enrichment failed for ${data.observable_value}: ${data.error || 'Unknown error'}`;
			case 'phase.changed':
				return `Phase changed: ${formatPhase(data.old_phase as string) || '?'} → ${formatPhase(data.new_phase as string || data.phase as string) || '?'}`;
			case 'verdict.rendered':
			case 'verdict.proposed': {
				const sopBadge = data.sop_verdict ? ` [${data.sop_verdict}]` : '';
				return `Verdict${sopBadge}: ${formatDecision(data.decision as string)} (${Math.round((data.confidence as number || 0) * 100)}% confidence)`;
			}
			case 'human.review_requested':
			case 'review.requested':
				return `Human review requested: ${data.reason || 'Manual review required'}`;
			case 'human.decision_received':
				return `Human decision: ${formatDecision(data.decision as string)}`;
			case 'thehive.case_created':
				return `TheHive case created: ${data.case_id || 'Unknown'}`;
			case 'thehive.alert_promoted':
				return `Alert promoted to TheHive case`;
			case 'misp.ioc_matched':
				return `MISP IOC match found`;
			case 'misp.context_retrieved':
				return `MISP context retrieved`;
			case 'analyzer.invoked':
				return `Analyzer invoked: ${data.analyzer || 'Unknown'}`;
			case 'analyzer.completed':
				return `Analyzer completed: ${data.analyzer || 'Unknown'}`;
			case 'error.occurred':
				return `Error: ${data.message || data.error || 'Unknown error'}`;
			default:
				return formatEventType(eventType);
		}
	}

	function getEventDetails(eventType: string, data: Record<string, unknown>): Array<{label: string, value: string, highlight?: boolean, tooltip?: string, badgeClass?: string}> {
		const details: Array<{label: string, value: string, highlight?: boolean, tooltip?: string, badgeClass?: string}> = [];

		switch (eventType) {
			case 'alert_ingested':
			case 'alert.ingested':
			case 'alert.added':
			case 'alert.correlated': {
				if (data.rule_id) details.push({ label: 'Rule ID', value: String(data.rule_id) });
				if (data.severity) details.push({ label: 'Severity', value: String(data.severity).toUpperCase(), highlight: Number(data.severity) >= 8 });
				
				const action = data.action || (data.raw as Record<string, any> | undefined)?.action;
				if (action && String(action).toLowerCase() !== 'unknown') {
					const actionStr = String(action).toUpperCase();
					const isDropped = actionStr === 'DROPPED' || actionStr === 'BLOCKED' || actionStr === 'DENIED' || actionStr === 'QUARANTINED';
					details.push({
						label: 'Action',
						value: actionStr,
						highlight: !isDropped,
						badgeClass: isDropped ? 'text-emerald-400 font-bold' : 'text-error-400 font-bold'
					});
				}

				const firedTimes = data.fired_times || data.firedtimes || (data.raw as Record<string, any> | undefined)?.firedtimes;
				if (firedTimes && Number(firedTimes) > 1) {
					details.push({ 
						label: 'Burst', 
						value: `${firedTimes}x Events`, 
						highlight: true,
						badgeClass: 'text-amber-300 font-semibold'
					});
				} else if (data.event_count && Number(data.event_count) > 1) {
					details.push({ label: 'Coalesced', value: `${data.event_count}x` });
				}

				if (data.asset_ids && Array.isArray(data.asset_ids) && data.asset_ids.length > 0) {
					const assets = data.asset_ids as string[];
					const displayAssets = assets.length > 3 
						? `${assets.slice(0, 3).join(', ')} (+${assets.length - 3} more)` 
						: assets.join(', ');
					details.push({ 
						label: 'Assets', 
						value: displayAssets,
						tooltip: assets.join(', ')
					});
				}
				if (data.mitre && typeof data.mitre === 'object') {
					const mitreObj = data.mitre as Record<string, unknown>;
					const mitreIds = (mitreObj.ids as string[]) || (mitreObj.id ? [String(mitreObj.id)] : []);
					if (mitreIds.length > 0) details.push({ label: 'MITRE', value: mitreIds.join(', ') });
				}
				if (data.rule_groups && Array.isArray(data.rule_groups) && data.rule_groups.length > 0) {
					const groups = data.rule_groups as string[];
					const displayGroups = groups.length > 2 
						? `${groups.slice(0, 2).join(', ')} (+${groups.length - 2} more)` 
						: groups.join(', ');
					details.push({ 
						label: 'Groups', 
						value: displayGroups,
						tooltip: groups.join(', ')
					});
				}
				if (data.initial_iocs && Array.isArray(data.initial_iocs) && data.initial_iocs.length > 0) {
					const iocVals = (data.initial_iocs as any[])
						.map((i: any) => (typeof i === 'object' && i !== null ? i.value : i))
						.filter(Boolean);
					if (iocVals.length > 0) {
						const formatIoc = (val: string) => {
							const s = String(val);
							if (s.startsWith('http://') || s.startsWith('https://')) {
								try {
									const u = new URL(s);
									const pathSnippet = u.pathname.length > 15 ? u.pathname.slice(0, 15) + '...' : u.pathname;
									return `${u.hostname}${pathSnippet}`;
								} catch {
									return s.length > 30 ? s.slice(0, 30) + '...' : s;
								}
							}
							return s.length > 30 ? s.slice(0, 30) + '...' : s;
						};

						const displayIocs = iocVals.length > 2
							? `${iocVals.slice(0, 2).map(formatIoc).join(', ')} (+${iocVals.length - 2} more)`
							: iocVals.map(formatIoc).join(', ');

						details.push({
							label: 'IOCs',
							value: displayIocs,
							highlight: true,
							tooltip: iocVals.join('\n')
						});
					}
				}
				if (data.source_event_id) details.push({ label: 'Event ID', value: String(data.source_event_id) });
				break;
			}

			case 'investigation.created':
				if (data.alert_ids) details.push({ label: 'Alerts', value: `${(data.alert_ids as string[]).length} alerts` });
				if (data.source_ip) details.push({ label: 'Source IP', value: String(data.source_ip) });
				if (data.source_agent) details.push({ label: 'Agent', value: String(data.source_agent) });
				if (data.max_severity) details.push({ label: 'Severity', value: String(data.max_severity).toUpperCase(), highlight: true });
				break;
			case 'observable.extracted':
				if (data.classification) details.push({ label: 'Classification', value: String(data.classification) });
				break;
			case 'enrichment.completed': {
				const result = data.result as Record<string, number> | undefined;
				if (result) {
					if (typeof result.malicious === 'number') details.push({ label: 'Malicious', value: String(result.malicious), highlight: result.malicious > 0 });
					if (typeof result.suspicious === 'number') details.push({ label: 'Suspicious', value: String(result.suspicious) });
					if (typeof result.harmless === 'number') details.push({ label: 'Harmless', value: String(result.harmless) });
				}
				break;
			}
			case 'verdict.rendered':
			case 'verdict.proposed':
				if (data.sop_verdict) details.push({ label: 'SOP Verdict', value: String(data.sop_verdict), highlight: true });
				if (data.assessment) details.push({ label: 'Assessment', value: String(data.assessment) });
				if (data.recommendation) details.push({ label: 'Recommendation', value: String(data.recommendation) });
				if (data.evidence) {
					const evidence = data.evidence as string[];
					evidence.forEach((e, i) => details.push({ label: i === 0 ? 'Evidence' : '', value: e }));
				}
				break;
		}

		return details;
	}

	$: investigationId = $page.params.id as string;

	onMount(async () => {
		if (!investigationId) return;
		await loadInvestigation();
		await loadEvents();
	});

	async function refreshInvestigation() {
		if (!investigationId) return;
		investigation = await api.investigations.get(investigationId);
	}

	async function loadInvestigation() {
		if (!investigationId) return;
		loading = true;
		error = null;
		try {
			await refreshInvestigation();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load investigation';
		} finally {
			loading = false;
		}
	}

	async function loadEvents() {
		if (!investigationId) return;
		eventsLoading = true;
		try {
			events = await api.investigations.getEvents(investigationId, 100);
		} catch (e) {
			console.error('Failed to load events:', e);
		} finally {
			eventsLoading = false;
		}
	}

	async function handleCancel() {
		if (!investigationId) return;
		actionLoading = true;
		try {
			const result = await api.investigations.cancel(investigationId, cancelReason);
			await Promise.all([refreshInvestigation(), loadEvents()]);
			addToast({ type: 'success', message: result.message });
			showCancelModal = false;
			cancelReason = '';
		} catch (e) {
			addToast({ type: 'error', message: e instanceof Error ? e.message : 'Failed to cancel' });
		} finally {
			actionLoading = false;
		}
	}

	function getStatusBadge(status: string): string {
		switch (status) {
			case 'pending': return 'variant-soft-warning';
			case 'in_progress': return 'variant-soft-primary';
			case 'paused': return 'variant-soft-tertiary';
			case 'closed':
			case 'auto_closed':
			case 'auto_closed_fp':
			case 'closed_fp':
			case 'closed_tp':
				return 'variant-soft-success';
			case 'escalated':
			case 'rejected':
				return 'variant-soft-error';
			case 'cancelled':
				return 'variant-soft';
			default: return 'variant-soft';
		}
	}

	function getSeverityBadge(severity: string | number | null): string {
		if (typeof severity === 'number') {
			if (severity >= 12) return 'variant-filled-error';
			if (severity >= 8) return 'variant-filled-warning';
			if (severity >= 4) return 'variant-filled-secondary';
			return 'variant-filled-tertiary';
		}
		switch (severity?.toLowerCase()) {
			case 'critical': return 'variant-filled-error';
			case 'high': return 'variant-filled-warning';
			case 'medium': return 'variant-filled-secondary';
			case 'low': return 'variant-filled-tertiary';
			default: return 'variant-soft';
		}
	}

	function getVerdictBadge(verdict: string | null): string {
		switch (verdict) {
			case 'escalate': return 'variant-filled-error';
			case 'needs_more_info':
			case 'suspicious':
				return 'variant-filled-warning';
			case 'close':
			case 'auto_close':
				return 'variant-filled-success';
			default: return 'variant-soft';
		}
	}

	function getSOPVerdictBadge(sopV: string | null | undefined): string {
		switch (sopV) {
			case 'True Positive – Malicious':
				return 'variant-filled-error';
			case 'True Positive – Benign / Expected':
				return 'variant-filled-secondary';
			case 'False Positive':
				return 'variant-filled-success';
			case 'Validation Required':
				return 'variant-filled-warning';
			default:
				return 'variant-soft-primary';
		}
	}

	function getEventIcon(eventType: string): string {
		switch (eventType) {
			case 'investigation.created':
				return 'M12 4v16m8-8H4';
			case 'investigation.closed':
				return 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z';
			case 'alert.added':
			case 'alert_ingested':
			case 'alert.ingested':
				return 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z';
			case 'observable.extracted':
				return 'M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z';
			case 'enrichment.requested':
			case 'enrichment.completed':
			case 'enrichment.failed':
				return 'M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z';
			case 'verdict.rendered':
				return 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z';
			case 'human.review_requested':
			case 'human.decision_received':
				return 'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z';
			case 'thehive.case_created':
				return 'M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z';
			case 'phase.changed':
				return 'M13 9l3 3m0 0l-3 3m3-3H8m13 0a9 9 0 11-18 0 9 9 0 0118 0z';
			default:
				return 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z';
		}
	}

	function getEventColor(eventType: string): string {
		if (eventType.includes('error') || eventType.includes('failed')) return 'text-error-500';
		if (eventType.includes('verdict') || eventType.includes('closed')) return 'text-success-500';
		if (eventType.includes('review') || eventType.includes('human')) return 'text-warning-500';
		if (eventType.includes('enrichment')) return 'text-secondary-500';
		return 'text-primary-500';
	}
</script>

<svelte:head>
	<title>{investigation?.title || 'Investigation'} - SocTalk</title>
</svelte:head>

{#if !loading && investigation}
	<button
		type="button"
		class="chat-launcher btn variant-filled-primary"
		on:click={() => (chatOpen = !chatOpen)}
		title="Ask the SOC AI about this investigation"
	>
		<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
			<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
		</svg>
		{chatOpen ? 'Close chat' : 'Ask AI'}
	</button>
	{#if chatOpen}
		<aside class="chat-dock">
			<ChatPanel investigationId={investigation.id} />
		</aside>
	{/if}
{/if}

{#if loading}
	<div class="flex items-center justify-center h-64">
		<div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500"></div>
	</div>
{:else if error}
	<div class="alert variant-filled-error">
		<span>Error: {error}</span>
	</div>
{:else if investigation}
	<div class="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4 mb-6">
		<div>
			<div class="flex items-center gap-2 mb-2">
				<a href="/investigations" class="btn btn-sm variant-soft">
					<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
					</svg>
					Back
				</a>
			</div>
			<h1 class="h2">{investigation.title || 'Untitled Investigation'}</h1>
			<div class="flex flex-wrap items-center gap-2 mt-2">
				<span class="badge {getStatusBadge(investigation.status)}">{formatStatus(investigation.status)}</span>
				<span class="badge variant-soft">{formatPhase(investigation.phase)}</span>
				{#if investigation.max_severity}
					<span class="badge {getSeverityBadge(investigation.max_severity)}">{formatSeverity(investigation.max_severity)}</span>
				{/if}
				{#if sopVerdict}
					<span class="badge {getSOPVerdictBadge(sopVerdict)} font-semibold">{sopVerdict}</span>
				{/if}
				{#if investigation.verdict_decision && !sopVerdict}
					<span class="badge {getVerdictBadge(investigation.verdict_decision)}">{formatDecision(investigation.verdict_decision)}</span>
				{/if}
				{#each investigation.tags as tag}
					<span class="badge variant-ghost">{tag}</span>
				{/each}
			</div>
		</div>

		<div class="flex gap-2">
			{#if !['closed', 'auto_closed_fp', 'closed_fp', 'closed_tp', 'cancelled'].includes(investigation.status)}
				<button
					class="btn variant-soft-error"
					disabled={actionLoading}
					on:click={() => (showCancelModal = true)}
				>
					<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
					</svg>
					Cancel
				</button>
			{/if}
		</div>
	</div>

	<!-- Primary KPI Summary Metrics (Immediate Visibility) -->
	<div class="grid grid-cols-2 lg:grid-cols-6 gap-4 mb-6">
		<div class="card p-3">
			<h4 class="text-xs opacity-60">Alerts</h4>
			<p class="text-2xl font-bold">{investigation.alert_count}</p>
		</div>
		<div class="card p-3">
			<h4 class="text-xs opacity-60">Observables</h4>
			<p class="text-2xl font-bold">{investigation.observable_count}</p>
		</div>
		<div class="card p-3">
			<h4 class="text-xs opacity-60 text-error-500">Malicious</h4>
			<p class="text-2xl font-bold text-error-500">{investigation.malicious_count}</p>
		</div>
		<div class="card p-3">
			<h4 class="text-xs opacity-60 text-warning-500">Suspicious</h4>
			<p class="text-2xl font-bold text-warning-500">{investigation.suspicious_count}</p>
		</div>
		<div class="card p-3">
			<h4 class="text-xs opacity-60">Time to Triage</h4>
			<p class="text-2xl font-bold">{formatDuration(investigation.time_to_triage_seconds)}</p>
		</div>
		<div class="card p-3">
			<h4 class="text-xs opacity-60">Time to Verdict</h4>
			<p class="text-2xl font-bold">{formatDuration(investigation.time_to_verdict_seconds)}</p>
		</div>
	</div>

	<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
		<div class="space-y-6">
			<div class="card p-4">
				<h3 class="h4 mb-4">Details</h3>
				<dl class="space-y-2">
					<div class="flex justify-between">
						<dt class="opacity-60">Short ID</dt>
						<dd class="font-mono text-xs font-bold text-primary-400">{investigation.short_id || investigation.id.slice(0, 8)}</dd>
					</div>
					<div class="flex justify-between">
						<dt class="opacity-60">ID</dt>
						<dd class="font-mono text-xs">{investigation.id.slice(0, 8)}...</dd>
					</div>
					<div class="flex justify-between">
						<dt class="opacity-60">Created</dt>
						<dd>{new Date(investigation.created_at).toLocaleString()}</dd>
					</div>
					<div class="flex justify-between">
						<dt class="opacity-60">Updated</dt>
						<dd>{new Date(investigation.updated_at).toLocaleString()}</dd>
					</div>
					{#if investigation.closed_at}
						<div class="flex justify-between">
							<dt class="opacity-60">Closed</dt>
							<dd>{new Date(investigation.closed_at).toLocaleString()}</dd>
						</div>
					{/if}
					{#if jiraIssueKey}
						<div class="flex justify-between">
							<dt class="opacity-60">Jira Ticket</dt>
							<dd class="badge variant-filled-primary font-mono">{jiraIssueKey}</dd>
						</div>
					{/if}
					{#if investigation.thehive_case_id}
						<div class="flex justify-between">
							<dt class="opacity-60">TheHive Case</dt>
							<dd class="font-mono text-sm">{investigation.thehive_case_id}</dd>
						</div>
					{/if}
					{#if investigation.threat_actor}
						<div class="flex justify-between">
							<dt class="opacity-60">Threat Actor</dt>
							<dd class="badge variant-filled-error">{investigation.threat_actor}</dd>
						</div>
					{/if}
				</dl>
			</div>

			{#if investigation.verdict_decision || sopVerdict}
				<div class="card p-4">
					<h3 class="h4 mb-4">Verdict & SOP Assessment</h3>
					<div class="space-y-3">
						{#if sopVerdict}
							<div class="flex items-center justify-between">
								<span class="opacity-60">SOP Classification</span>
								<span class="badge {getSOPVerdictBadge(sopVerdict)} text-sm px-2.5 py-1 font-bold">
									{sopVerdict}
								</span>
							</div>
						{/if}
						<div class="flex items-center justify-between">
							<span class="opacity-60">Action Decision</span>
							<span class="badge {getVerdictBadge(investigation.verdict_decision)} text-base px-3 py-1">
								{formatDecision(investigation.verdict_decision)}
							</span>
						</div>
						{#if investigation.verdict_confidence}
							<div>
								<div class="flex justify-between text-sm mb-1">
									<span class="opacity-60">Confidence</span>
									<span>{(investigation.verdict_confidence * 100).toFixed(0)}%</span>
								</div>
								<div class="w-full h-2 bg-surface-500/30 rounded-full overflow-hidden">
									<div
										class="h-full rounded-full transition-all duration-300
											{investigation.verdict_confidence > 0.8 ? 'bg-success-500' :
											 investigation.verdict_confidence > 0.5 ? 'bg-warning-500' : 'bg-error-500'}"
										style="width: {investigation.verdict_confidence * 100}%"
									></div>
								</div>
							</div>
						{/if}
						{#if investigation.verdict_reasoning}
							<div>
								<span class="opacity-60 text-sm">Reasoning & SOP Report</span>
								<div class="mt-1 text-xs bg-surface-900 border border-surface-700 rounded p-3 max-h-96 overflow-y-auto whitespace-pre-wrap font-sans text-surface-200 selection:bg-primary-900">
									{investigation.verdict_reasoning}
								</div>
							</div>
						{/if}
					</div>
				</div>
			{/if}

			<!-- Agent Run Card with Unified OODA Stepper -->
			<div class="card p-4">
				<h3 class="h4 mb-4">Agent Run</h3>
				<div class="space-y-4">
					{#if investigation.tokens_used !== null && investigation.tokens_used !== undefined}
						{#if !$isCustomerScope}
							<div>
								<div class="flex justify-between text-sm mb-1">
									<span class="opacity-60">Token Spend</span>
									<span class="font-mono text-xs">
										{investigation.tokens_used?.toLocaleString() ?? 0}
										{#if investigation.tokens_budget}
											/ {investigation.tokens_budget.toLocaleString()}
										{/if}
									</span>
								</div>
								{#if investigation.tokens_budget}
									{@const ratio = Math.min(1, (investigation.tokens_used ?? 0) / investigation.tokens_budget)}
									<div class="w-full h-2 bg-surface-500/30 rounded-full overflow-hidden">
										<div
											class="h-full rounded-full transition-all duration-300
												{ratio > 0.8 ? 'bg-error-500' : ratio > 0.5 ? 'bg-warning-500' : 'bg-success-500'}"
											style="width: {ratio * 100}%"
										></div>
									</div>
								{/if}
							</div>
							{#if investigation.disposition}
								<div class="flex items-center justify-between">
									<span class="opacity-60 text-sm">Disposition</span>
									<span class="badge {investigation.disposition === 'escalate' ? 'variant-filled-error' : investigation.disposition === 'close_fp' ? 'variant-filled-success' : investigation.disposition === 'halted_budget' ? 'variant-filled-warning' : 'variant-filled-surface'}">
										{investigation.disposition.replace('_', ' ')}
									</span>
								</div>
							{/if}
						{/if}
					{/if}

					<!-- Compact OODA Pipeline Status -->
					<div class="pt-2 border-t border-surface-700/60">
						<span class="text-xs font-semibold opacity-60 uppercase tracking-wider block mb-2">OODA Stage</span>
						<div class="space-y-1.5">
							{#each oodaStages as stage}
								<div class="flex items-center justify-between text-xs p-1.5 rounded bg-surface-900/60 border border-surface-700/40">
									<span class="font-medium {stage.isDone ? 'text-primary-300' : 'text-surface-400'}">
										{stage.step}. {stage.name}
									</span>
									{#if stage.isDone}
										<span class="text-[10px] text-emerald-400 font-mono font-bold">READY</span>
									{:else if stage.isActive}
										<span class="text-[10px] text-amber-300 font-mono animate-pulse font-bold">RUNNING</span>
									{:else}
										<span class="text-[10px] text-surface-500 font-mono">PENDING</span>
									{/if}
								</div>
							{/each}
						</div>
					</div>
				</div>
			</div>

			<div class="card p-4">
				<h3 class="h4 mb-4">Observable Summary</h3>
				<div class="space-y-2">
					<div class="flex items-center justify-between">
						<span>Total</span>
						<span class="font-mono">{investigation.observable_count}</span>
					</div>
					<div class="flex items-center justify-between">
						<span class="flex items-center gap-2">
							<span class="w-2 h-2 rounded-full bg-error-500"></span>
							Malicious
						</span>
						<span class="font-mono text-error-500">{investigation.malicious_count}</span>
					</div>
					<div class="flex items-center justify-between">
						<span class="flex items-center gap-2">
							<span class="w-2 h-2 rounded-full bg-warning-500"></span>
							Suspicious
						</span>
						<span class="font-mono text-warning-500">{investigation.suspicious_count}</span>
					</div>
					<div class="flex items-center justify-between">
						<span class="flex items-center gap-2">
							<span class="w-2 h-2 rounded-full bg-success-500"></span>
							Clean
						</span>
						<span class="font-mono text-success-500">{investigation.clean_count}</span>
					</div>
				</div>
			</div>
		</div>

		<div class="lg:col-span-2">
			<div class="card p-4">
				<div class="flex items-center justify-between mb-4">
					<h3 class="h4">Event Timeline</h3>
					<button class="btn btn-sm variant-soft" on:click={loadEvents} disabled={eventsLoading}>
						{#if eventsLoading}
							<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></span>
						{/if}
						Refresh
					</button>
				</div>

				{#if eventsLoading && events.length === 0}
					<div class="flex items-center justify-center py-8">
						<div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
					</div>
				{:else if events.length === 0}
					<p class="opacity-60 text-center py-8">No events recorded</p>
				{:else}
					<div class="space-y-4 max-h-[calc(100vh-14rem)] overflow-y-auto pr-2">
						{#each events as event, i}
							{@const eventKey = getEventKey(event, i)}
							{@const currentMode = eventViewMode[eventKey] || 'json'}
							{@const details = getEventDetails(event.event_type, event.data)}
							<div class="flex gap-3">
								<div class="flex flex-col items-center">
									<div class="w-8 h-8 rounded-full bg-surface-500/30 flex items-center justify-center {getEventColor(event.event_type)}">
										<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
											<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d={getEventIcon(event.event_type)} />
										</svg>
									</div>
									{#if i < events.length - 1}
										<div class="w-0.5 h-full min-h-8 bg-surface-500/30 my-1"></div>
									{/if}
								</div>

								<div class="flex-1 pb-4">
									<div class="flex items-center gap-2 mb-1">
										<span class="badge variant-soft text-xs">{formatEventType(event.event_type)}</span>
										<span class="text-xs opacity-60">
											{new Date(event.timestamp).toLocaleString()}
										</span>
									</div>
									<p class="text-sm font-medium mb-2">{formatEventSummary(event.event_type, event.data)}</p>

									{#if details.length > 0}
										<div class="flex flex-wrap gap-1.5 text-xs mb-3">
											{#each details as detail}
												<span
													class="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-surface-800 border border-surface-700 {detail.tooltip ? 'cursor-help' : ''}"
													title={detail.tooltip || detail.value}
												>
													<span class="opacity-50 font-medium">{detail.label}:</span>
													<span class="{detail.badgeClass || (detail.highlight ? 'text-error-400 font-semibold' : 'text-surface-200')}">{detail.value}</span>
												</span>
											{/each}
										</div>
									{/if}

									<button
										class="text-xs opacity-60 hover:opacity-100 flex items-center gap-1 transition-opacity"
										on:click={() => toggleEventDetails(eventKey)}
									>
										<svg
											xmlns="http://www.w3.org/2000/svg"
											class="h-3 w-3 transition-transform {expandedEvents.has(eventKey) ? 'rotate-90' : ''}"
											fill="none"
											viewBox="0 0 24 24"
											stroke="currentColor"
										>
											<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
										</svg>
										{expandedEvents.has(eventKey) ? 'Hide' : 'Show'} raw data
									</button>

									{#if expandedEvents.has(eventKey)}
										<div class="mt-2 rounded-lg bg-surface-900 border border-surface-700 p-4 space-y-4">
											{#if extractRawLog(event.data)}
												{@const rawLog = extractRawLog(event.data)}
												<div class="space-y-2">
													<div class="flex items-center justify-between pb-1 border-b border-surface-700">
														<span class="text-xs font-semibold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
															<span class="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
															Raw Wazuh Telemetry (full_log)
														</span>
														<button
															type="button"
															on:click={() => copyToClipboard(rawLog, eventKey)}
															class="btn btn-sm variant-soft-primary text-xs py-1 px-2.5"
														>
															{copiedLogId === eventKey ? '✅ Copied to Clipboard!' : '📋 Copy Log'}
														</button>
													</div>
													<pre class="overflow-y-auto rounded bg-black/70 p-3.5 font-mono text-xs text-emerald-400 whitespace-pre-wrap break-all max-h-80 selection:bg-emerald-900 selection:text-white border border-surface-700/80 leading-relaxed">{rawLog}</pre>
												</div>
											{/if}

											<!-- Directly Open Structured Metadata (Reactive Table & JSON Switch) -->
											<div class="pt-2 border-t border-surface-700/60 space-y-2">
												<div class="flex items-center justify-between">
													<span class="text-xs font-semibold uppercase tracking-wider text-surface-300">
														Structured Event Metadata
													</span>
													<div class="flex items-center gap-2">
														<div class="inline-flex rounded-md shadow-sm border border-surface-700 overflow-hidden text-xs">
															<button
																type="button"
																class="px-2.5 py-0.5 font-medium transition-colors {currentMode === 'json' ? 'bg-primary-600 text-white' : 'bg-surface-800 text-surface-300 hover:bg-surface-700'}"
																on:click={() => setViewMode(eventKey, 'json')}
															>
																JSON
															</button>
															<button
																type="button"
																class="px-2.5 py-0.5 font-medium transition-colors border-l border-surface-700 {currentMode === 'table' ? 'bg-primary-600 text-white' : 'bg-surface-800 text-surface-300 hover:bg-surface-700'}"
																on:click={() => setViewMode(eventKey, 'table')}
															>
																Table
															</button>
														</div>
														<button
															type="button"
															on:click={() => copyToClipboard(JSON.stringify(event.data, null, 2), `${eventKey}-json`)}
															class="btn btn-sm variant-soft text-xs py-0.5 px-2"
														>
															{copiedLogId === `${eventKey}-json` ? '✅ Copied JSON!' : '📋 Copy JSON'}
														</button>
													</div>
												</div>

												{#if currentMode === 'json'}
													<pre class="text-xs overflow-y-auto whitespace-pre-wrap break-all font-mono text-surface-300 bg-black/60 p-3.5 rounded border border-surface-700/80 max-h-[480px] leading-relaxed select-all">{JSON.stringify(event.data, null, 2)}</pre>
												{:else}
													{@const metaRows = getStructuredMetadata(event.data)}
													{#if metaRows.length > 0}
														<div class="max-h-[480px] overflow-y-auto rounded border border-surface-700/80 bg-black/50">
															<table class="w-full text-left border-collapse">
																<thead class="sticky top-0 bg-surface-800 border-b border-surface-700 z-10">
																	<tr class="text-[11px] text-surface-400 uppercase tracking-wider">
																		<th class="py-2 px-3 font-semibold w-1/3">Field</th>
																		<th class="py-2 px-3 font-semibold">Value</th>
																	</tr>
																</thead>
																<tbody class="divide-y divide-surface-800 text-xs">
																	{#each metaRows as row}
																		<tr class="hover:bg-surface-800/50 transition-colors">
																			<td class="py-1.5 px-3 font-mono text-primary-300 whitespace-nowrap align-top select-all font-medium">
																				{row.key}
																			</td>
																			<td class="py-1.5 px-3 font-mono text-surface-200 break-all select-all">
																				{row.value}
																			</td>
																		</tr>
																	{/each}
																</tbody>
															</table>
														</div>
													{:else}
														<p class="text-xs opacity-60 italic py-2">No structured metadata attributes found.</p>
													{/if}
												{/if}
											</div>
										</div>
									{/if}
								</div>
							</div>
						{/each}
					</div>
				{/if}
			</div>
		</div>
	</div>
{/if}

{#if showCancelModal}
	<div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
		<div class="card p-6 w-full max-w-md m-4">
			<h3 class="h3 mb-4">Cancel Investigation</h3>
			<p class="mb-4 opacity-80">Are you sure you want to cancel this investigation?</p>
			<label class="label mb-4">
				<span>Reason (optional)</span>
				<textarea
					class="textarea"
					rows="3"
					bind:value={cancelReason}
					placeholder="Provide a reason for cancellation..."
				></textarea>
			</label>
			<div class="flex justify-end gap-2">
				<button
					class="btn variant-soft"
					on:click={() => { showCancelModal = false; cancelReason = ''; }}
				>
					Keep Investigation
				</button>
				<button
					class="btn variant-filled-error"
					disabled={actionLoading}
					on:click={handleCancel}
				>
					{#if actionLoading}
						<span class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></span>
					{/if}
					Cancel Investigation
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.chat-launcher {
		position: fixed;
		bottom: 1.5rem;
		right: 1.5rem;
		z-index: 60;
		box-shadow: 0 8px 20px rgba(0, 0, 0, 0.25);
	}
	.chat-dock {
		position: fixed;
		bottom: 5rem;
		right: 1.5rem;
		width: min(420px, calc(100vw - 3rem));
		height: min(70vh, 640px);
		z-index: 55;
		box-shadow: 0 12px 32px rgba(0, 0, 0, 0.35);
		border-radius: 0.75rem;
		overflow: hidden;
	}
	@media (max-width: 640px) {
		.chat-dock {
			right: 0.75rem;
			bottom: 4.5rem;
			width: calc(100vw - 1.5rem);
		}
	}
</style>