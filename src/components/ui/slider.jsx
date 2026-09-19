import { Slider as SliderPrimitive } from "@base-ui/react/slider"
import { cn } from "cn"

/**
 * Base UI reports a single-thumb slider's value inconsistently:
 *
 *   SliderRoot.js   `range = Array.isArray(valueUnwrapped)`  -> emits an array
 *   SliderControl.js `range = values.length > 1`             -> emits a number
 *
 * So a slider controlled with `[15000]` gives back `[22000]` from the keyboard
 * but a bare `22000` from a pointer drag. A caller holding array state then
 * has a number, `value[0]` is undefined, and the next render throws.
 *
 * This normalises the outgoing value to the shape the caller passed in, so
 * consumers get back what they gave regardless of how the user moved it.
 */
function Slider({
  className,
  defaultValue,
  value,
  min = 0,
  max = 100,
  onValueChange,
  ...props
}) {
  const controlledWithArray =
    Array.isArray(value) || (value === undefined && Array.isArray(defaultValue))

  const handleValueChange = onValueChange
    ? (next, ...rest) => {
        const normalised = controlledWithArray
          ? (Array.isArray(next) ? next : [next])
          : (Array.isArray(next) ? next[0] : next)
        onValueChange(normalised, ...rest)
      }
    : undefined

  const _values = Array.isArray(value)
    ? value
    : Array.isArray(defaultValue)
      ? defaultValue
      : [min, max]

  return (
    <SliderPrimitive.Root
      className={cn("data-horizontal:w-full data-vertical:h-full", className)}
      data-slot="slider"
      defaultValue={defaultValue}
      value={value}
      min={min}
      max={max}
      onValueChange={handleValueChange}
      thumbAlignment="edge"
      {...props}
    >
      <SliderPrimitive.Control className="relative flex w-full touch-none items-center select-none data-disabled:opacity-50 data-vertical:h-full data-vertical:min-h-40 data-vertical:w-auto data-vertical:flex-col">
        <SliderPrimitive.Track
          data-slot="slider-track"
          className="relative grow overflow-hidden rounded-full bg-muted select-none data-horizontal:h-1 data-horizontal:w-full data-vertical:h-full data-vertical:w-1"
        >
          <SliderPrimitive.Indicator
            data-slot="slider-range"
            className="bg-primary select-none data-horizontal:h-full data-vertical:w-full"
          />
        </SliderPrimitive.Track>
        {Array.from({ length: _values.length }, (_, index) => (
          <SliderPrimitive.Thumb
            data-slot="slider-thumb"
            key={index}
            className="relative block size-3 shrink-0 rounded-full border border-ring bg-white ring-ring/50 transition-[color,box-shadow] select-none after:absolute after:-inset-2 hover:ring-3 focus-visible:ring-3 focus-visible:outline-hidden active:ring-3 disabled:pointer-events-none disabled:opacity-50"
          />
        ))}
      </SliderPrimitive.Control>
    </SliderPrimitive.Root>
  )
}

export { Slider }
