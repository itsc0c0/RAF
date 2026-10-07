import { NavLink } from 'react-router-dom';
import { useProducts, useVersion } from '../api/hooks';
import { Icon } from '../components/Icon';
import { cx } from '../lib/cx';
import { NAV_ITEMS } from './navigation';

export function LeftNav({ collapsed }: { collapsed: boolean }) {
  const products = useProducts();
  const version = useVersion();
  const available = products.data
    ? new Set(products.data.items.filter((p) => p.available && p.enabled).map((p) => p.name))
    : null;

  return (
    <nav className={cx('nav', collapsed && 'nav--collapsed')} aria-label="Primary">
      <ul className="nav__list">
        {NAV_ITEMS.map((item) => {
          const missing = Boolean(
            available && item.products && !item.products.some((name) => available.has(name)),
          );
          return (
            <li key={item.path}>
              <NavLink
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  cx('nav__link', isActive && 'is-active', missing && 'is-unavailable')
                }
                title={collapsed ? item.label : item.description}
                aria-label={collapsed ? item.label : undefined}
              >
                <Icon name={item.icon} size={17} />
                <span className="nav__label">{item.label}</span>
                {missing && !collapsed ? (
                  <span className="nav__na" title="Not available in this installation yet">
                    n/a
                  </span>
                ) : null}
              </NavLink>
            </li>
          );
        })}
      </ul>
      {!collapsed ? (
        <p className="nav__footer small faint">
          R$F {version.data?.raf ?? ''} · API {version.data?.api ?? 'v1'}
        </p>
      ) : null}
    </nav>
  );
}
