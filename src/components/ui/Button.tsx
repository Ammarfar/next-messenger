import { cn } from '@/lib/utils'
import { cva, VariantProps } from 'class-variance-authority'
import { Loader2 } from 'lucide-react'
import { ButtonHTMLAttributes, FC } from 'react'

const buttonVariants = cva(
  'active:scale-95 inline-flex items-center justify-center rounded-md text-sm font-medium transition-color disabled:opacity-50 disabled:pointer-events-none',
  {
    variants: {
      variant: {
        'primary': 'bg-slate-900 text-white hover:bg-slate-800',
        'secondary': 'bg-transparent hover:text-slate-900 hover:bg-slate-200',
      },
      size: {
        'default': 'h-10 py-2 px-4',
        'sm': 'h-9 px-2',
        'lg': 'h-11 px-8',
      }
    },
    defaultVariants: {
      variant: 'primary',
      size: 'default',
    }
  }
)

export interface buttonProps<T> extends ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> {
  isLoading?: boolean
}

const Button: FC<buttonProps<HTMLButtonElement>> = ({
  isLoading,
  variant,
  size,
  className,
  children,
  ...props
}) => {
  return <button
    className={cn(buttonVariants({ variant, size, className }))}
    disabled={isLoading}
    {...props}
  >
    {isLoading ? <Loader2 className='mr-2 h-4 w-4 animate-spin' /> : null}
    {children}
  </button>
}

export default Button