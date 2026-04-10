'use client';

import { AlertCircle, Plus, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { useToast } from '@/hooks/use-toast';

export default function ImagesPage() {
  const { toast } = useToast();

  return (
    <div className="container mx-auto py-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Base Images</h1>
          <p className="text-muted-foreground mt-1">
            Manage base images for VMs and containers
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="icon" disabled>
            <RefreshCw className="h-4 w-4" />
          </Button>
          <Button
            onClick={() =>
              toast({
                title: 'Feature Not Available',
                description: 'Image management API is not yet implemented',
                variant: 'default',
              })
            }
          >
            <Plus className="mr-2 h-4 w-4" />
            Pull from Registry
          </Button>
        </div>
      </div>

      <Alert>
        <AlertCircle className="h-4 w-4" />
        <AlertTitle>API Not Implemented</AlertTitle>
        <AlertDescription>
          The image management API endpoints are not yet available in the platform. This page will
          display base images for VMs and containers once the backend API is implemented with the
          following methods:
          <ul className="list-disc list-inside mt-2 ml-2">
            <li>listImages() - List all available base images</li>
            <li>getImage(id) - Get details of a specific image</li>
            <li>uploadImage() - Upload a custom image</li>
            <li>deleteImage(id) - Remove an image from the registry</li>
          </ul>
        </AlertDescription>
      </Alert>
    </div>
  );
}
