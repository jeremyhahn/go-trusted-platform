/**
 * QuicBaaS Scheduler Service
 *
 * Provides operations for job scheduling including creating, managing,
 * and executing scheduled jobs in the QuicBaaS distributed database.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  CreateJobRequest,
  CreateJobResponse,
  GetJobRequest,
  GetJobResponse,
  UpdateJobRequest,
  UpdateJobResponse,
  DeleteJobRequest,
  DeleteJobResponse,
  ListJobsRequest,
  ListJobsResponse,
  PauseJobRequest,
  PauseJobResponse,
  ResumeJobRequest,
  ResumeJobResponse,
  TriggerJobRequest,
  TriggerJobResponse,
} from '../../types/quicbaas/infrastructure-part2.js';

/**
 * QuicBaaS Scheduler Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a scheduled job
 * const job = await client.quicbaas.scheduler.createJob({
 *   name: 'daily-backup',
 *   type: 'backup',
 *   schedule: {
 *     type: 'cron',
 *     cronExpression: '0 2 * * *',
 *     timezone: 'UTC',
 *   },
 *   payload: { target: 'all-databases' },
 * });
 *
 * // Trigger the job immediately
 * const execution = await client.quicbaas.scheduler.triggerJob({
 *   jobId: job.data.job.id,
 * });
 *
 * // Pause the job
 * await client.quicbaas.scheduler.pauseJob({ jobId: job.data.job.id });
 * ```
 */
export class SchedulerService extends BaseService {
  /**
   * Creates a new Scheduler service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  // =========================================================================
  // Job Management
  // =========================================================================

  /**
   * Create a new scheduled job
   *
   * @param request - Job creation request
   * @returns Created job
   */
  async createJob(request: CreateJobRequest): Promise<ApiResponse<CreateJobResponse>> {
    return this.client.post<CreateJobResponse>(this.buildUrl('/scheduler/jobs'), request);
  }

  /**
   * Get a job by ID
   *
   * @param request - Get job request with job ID
   * @returns Job details
   */
  async getJob(request: GetJobRequest): Promise<ApiResponse<GetJobResponse>> {
    return this.client.get<GetJobResponse>(
      this.buildUrl(`/scheduler/jobs/${this.encodePathSegment(request.jobId)}`)
    );
  }

  /**
   * Update an existing job
   *
   * @param request - Job update request
   * @returns Updated job
   */
  async updateJob(request: UpdateJobRequest): Promise<ApiResponse<UpdateJobResponse>> {
    const { jobId, ...body } = request;
    return this.client.put<UpdateJobResponse>(
      this.buildUrl(`/scheduler/jobs/${this.encodePathSegment(jobId)}`),
      body
    );
  }

  /**
   * Delete a job
   *
   * @param request - Delete request with job ID
   * @returns Deletion result
   */
  async deleteJob(request: DeleteJobRequest): Promise<ApiResponse<DeleteJobResponse>> {
    const url = this.buildUrl(`/scheduler/jobs/${this.encodePathSegment(request.jobId)}`, {
      filters: {
        force: request.force?.toString(),
      },
    });
    return this.client.delete<DeleteJobResponse>(url);
  }

  /**
   * List all jobs with optional filtering
   *
   * @param request - List request with optional filters
   * @returns List of jobs
   */
  async listJobs(request?: ListJobsRequest): Promise<ApiResponse<ListJobsResponse>> {
    const filters: Record<string, string | undefined> = {};

    if (request?.status !== undefined) {
      filters.status = request.status;
    }
    if (request?.type !== undefined) {
      filters.type = request.type;
    }
    if (request?.priority !== undefined) {
      filters.priority = request.priority;
    }
    if (request?.labels !== undefined) {
      filters.labels = JSON.stringify(request.labels);
    }

    return this.client.get<ListJobsResponse>(
      this.buildUrl('/scheduler/jobs', {
        page: request?.page,
        limit: request?.pageSize,
        filters,
      })
    );
  }

  // =========================================================================
  // Job Control
  // =========================================================================

  /**
   * Pause a running or scheduled job
   *
   * @param request - Pause request with job ID
   * @returns Updated job in paused state
   */
  async pauseJob(request: PauseJobRequest): Promise<ApiResponse<PauseJobResponse>> {
    return this.client.post<PauseJobResponse>(
      this.buildUrl(`/scheduler/jobs/${this.encodePathSegment(request.jobId)}/pause`),
      {}
    );
  }

  /**
   * Resume a paused job
   *
   * @param request - Resume request with job ID
   * @returns Updated job in active state
   */
  async resumeJob(request: ResumeJobRequest): Promise<ApiResponse<ResumeJobResponse>> {
    return this.client.post<ResumeJobResponse>(
      this.buildUrl(`/scheduler/jobs/${this.encodePathSegment(request.jobId)}/resume`),
      {}
    );
  }

  /**
   * Trigger immediate execution of a job
   *
   * @param request - Trigger request with job ID and optional payload override
   * @returns Execution context for the triggered job
   */
  async triggerJob(request: TriggerJobRequest): Promise<ApiResponse<TriggerJobResponse>> {
    return this.client.post<TriggerJobResponse>(
      this.buildUrl(`/scheduler/jobs/${this.encodePathSegment(request.jobId)}/trigger`),
      { payloadOverride: request.payloadOverride }
    );
  }
}
