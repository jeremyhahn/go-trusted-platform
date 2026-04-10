"use client";

import * as React from "react";
import { Save, Loader2 } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";

interface ConfigSectionProps {
  title: string;
  description?: string;
  children: React.ReactNode;
  onSave: (data: Record<string, unknown>) => Promise<void>;
}

/**
 * Configuration section component
 * Provides a card layout with save functionality
 *
 * @example
 * ```tsx
 * <ConfigSection
 *   title="General Settings"
 *   description="Configure general platform settings"
 *   onSave={async (data) => {
 *     await platformApi.config.updateConfig('general', data);
 *   }}
 * >
 *   <Input name="name" label="Platform Name" />
 * </ConfigSection>
 * ```
 */
export function ConfigSection({
  title,
  description,
  children,
  onSave,
}: ConfigSectionProps) {
  const { toast } = useToast();
  const [isSaving, setIsSaving] = React.useState(false);
  const formRef = React.useRef<HTMLFormElement>(null);

  const handleSave = async () => {
    if (!formRef.current) return;

    setIsSaving(true);
    try {
      const formData = new FormData(formRef.current);
      const data: Record<string, unknown> = {};

      formData.forEach((value, key) => {
        // Handle checkboxes
        if (value === "on") {
          data[key] = true;
        } else if (value === "off") {
          data[key] = false;
        } else {
          // Try to parse as number if possible
          const numValue = Number(value);
          data[key] = isNaN(numValue) ? value : numValue;
        }
      });

      await onSave(data);

      toast({
        title: "Settings saved",
        description: "Your configuration has been updated successfully.",
      });
    } catch (error) {
      toast({
        title: "Error saving settings",
        description: error instanceof Error ? error.message : "An error occurred",
        variant: "destructive",
      });
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <form ref={formRef}>
        <CardContent className="space-y-4">{children}</CardContent>
        <CardFooter>
          <Button
            type="button"
            onClick={handleSave}
            disabled={isSaving}
            className="ml-auto"
          >
            {isSaving ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Saving...
              </>
            ) : (
              <>
                <Save className="mr-2 h-4 w-4" />
                Save
              </>
            )}
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}
